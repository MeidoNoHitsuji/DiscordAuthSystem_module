package pro.gravit.launchermodules.discordauthsystem;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import pro.gravit.launcher.ClientPermissions;
import pro.gravit.launcher.HTTPRequest;
import pro.gravit.launcher.Launcher;
import pro.gravit.launcher.config.JsonConfigurable;
import pro.gravit.launcher.modules.LauncherInitContext;
import pro.gravit.launcher.modules.LauncherModule;
import pro.gravit.launcher.modules.LauncherModuleInfo;
import pro.gravit.launcher.modules.events.ClosePhase;
import pro.gravit.launcher.modules.events.PreConfigPhase;
import pro.gravit.launchermodules.discordauthsystem.providers.DiscordSystemAuthCoreProvider;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.launchserver.modules.events.LaunchServerFullInitEvent;
import pro.gravit.launchserver.socket.handlers.NettyWebAPIHandler;
import pro.gravit.utils.Version;
import pro.gravit.utils.helper.IOHelper;
import pro.gravit.utils.helper.LogHelper;
import pro.gravit.utils.helper.SecurityHelper;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class DiscordAuthSystemModule extends LauncherModule {
    public static final Version version = new Version(1, 0, 0, 0, Version.Type.LTS);
    private static final Gson gson = new Gson();
    public JsonConfigurable<DiscordAuthSystemConfig> jsonConfigurable;
    public Set<UserSessionEntity> sessions = ConcurrentHashMap.newKeySet();
    public DiscordAuthSystemConfig config;
    private Path dbPath;

    public DiscordAuthSystemModule() {
        super(new LauncherModuleInfo("DiscordAuthSystem", version, new String[]{"LaunchServerCore"}));
    }

    @Override
    public void init(LauncherInitContext initContext) {
        registerEvent(this::finish, LaunchServerFullInitEvent.class);
        registerEvent(this::preConfig, PreConfigPhase.class);
        registerEvent(this::exit, ClosePhase.class);
        jsonConfigurable = modulesConfigManager.getConfigurable(DiscordAuthSystemConfig.class, moduleInfo.name);
        dbPath = modulesConfigManager.getModuleConfigDir(moduleInfo.name);
    }

    public void finish(LaunchServerFullInitEvent event) {
        LaunchServer launchServer = event.server;
        try {
            jsonConfigurable.loadConfig();
            config = jsonConfigurable.getConfig();
        } catch (IOException e) {
            LogHelper.error(e);
        }
        load();
        NettyWebAPIHandler.addNewSeverlet("auth/discord", new DiscordAuthWebApi(this, launchServer));
    }

    public void exit(ClosePhase closePhase) {
        if (jsonConfigurable != null && jsonConfigurable.getConfig() != null)
            save();
    }

    public void load() {
        load(dbPath);
    }

    public void load(Path path) {
        {
            Path sessionsPath = path.resolve("Sessions.json");
            if (!Files.exists(sessionsPath)) return;
            Type sessionsType = new TypeToken<Set<UserSessionEntity>>() {
            }.getType();
            try (Reader reader = IOHelper.newReader(sessionsPath)) {
                this.sessions = Launcher.gsonManager.configGson.fromJson(reader, sessionsType);
            } catch (IOException e) {
                LogHelper.error(e);
            }
            for (UserSessionEntity sessionEntity : sessions) {
                if (sessionEntity.userEntityUUID != null) {
                    sessionEntity.entity = getUserByUUID(sessionEntity.userEntityUUID);
                }
            }
        }
    }

    public void save() {
        save(dbPath);
    }

    public void save(Path path) {
        {
            Path sessionsPath = path.resolve("Sessions.json");
            Type sessionsType = new TypeToken<Set<UserSessionEntity>>() {
            }.getType();
            try (Writer writer = IOHelper.newWriter(sessionsPath)) {
                Launcher.gsonManager.configGson.toJson(sessions, sessionsType, writer);
            } catch (IOException e) {
                LogHelper.error(e);
            }
        }
    }

    public void preConfig(PreConfigPhase preConfigPhase) {
        AuthCoreProvider.providers.register("discordauthsystem", DiscordSystemAuthCoreProvider.class);
    }

    public DiscordUser getUser(JoinServerRequest request) {
        JsonElement responseUsername;
        JsonElement responseUUID;
        request.parameters = config.addParameters;
        try {
            JsonElement r = HTTPRequest.jsonRequest(gson.toJsonTree(request), new URL(config.backendUserUrl));
            if (r == null) {
                return null;
            }
            JsonObject response = r.getAsJsonObject();
            responseUsername = response.get("username");
            responseUUID = response.get("uuid");
        } catch (IllegalStateException | IOException ignore) {
            return null;
        }
        if (responseUsername != null && responseUUID != null) {
            return new DiscordUser(responseUsername.getAsString(), UUID.fromString(responseUUID.getAsString()));
        } else {
            return null;
        }
    }

    public UserSessionEntity getSessionByAccessToken(String accessToken) {
        return sessions.stream().filter(e -> e.accessToken != null && e.accessToken.equals(accessToken)).findFirst().orElse(null);
    }

    public UserSessionEntity getSessionByRefreshToken(String refreshToken) {
        return sessions.stream().filter(e -> e.accessToken != null && e.refreshToken.equals(refreshToken)).findFirst().orElse(null);
    }

    public void addNewSession(UserSessionEntity session) {
        sessions.add(session);
    }

    public boolean deleteSession(UserSessionEntity entity) {
        return sessions.remove(entity);
    }

    public boolean exitUser(DiscordUser user) {
        return sessions.removeIf(e -> e.entity == user);
    }

    public DiscordUser getUserByLogin(String login) {
        JoinServerRequest request = new JoinServerRequest();
        request.login = login;
        return this.getUser(request);
    }

    public DiscordUser getUserByUsername(String username) {
        JoinServerRequest request = new JoinServerRequest();
        request.username = username;
        return this.getUser(request);
    }

    public DiscordUser getUserByUUID(UUID uuid) {
        JoinServerRequest request = new JoinServerRequest();
        request.uuid = uuid;
        return this.getUser(request);
    }

    public static class JoinServerRequest {
        public String login;
        public String username;
        public UUID uuid;
        public Map<String, String> parameters;
    }

    public static class DiscordUser implements User {
        public String username;
        public UUID uuid;
        public ClientPermissions permissions;
        public String serverId;
        public String accessToken;

        public DiscordUser(String username, UUID uuid) {
            this.username = username;
            this.uuid = uuid;
            this.permissions = new ClientPermissions();
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public UUID getUUID() {
            return uuid;
        }

        @Override
        public String getServerId() {
            return serverId;
        }

        @Override
        public String getAccessToken() {
            return accessToken;
        }

        @Override
        public ClientPermissions getPermissions() {
            return permissions;
        }

        @Override
        public boolean isBanned() {
            return false;
        }
    }

    public static class UserSessionEntity implements UserSession {
        private final UUID uuid;
        public transient DiscordUser entity;
        public UUID userEntityUUID;
        public String accessToken;
        public String refreshToken;
        public long expireMillis;

        public UserSessionEntity(DiscordUser entity) {
            this.uuid = UUID.randomUUID();
            this.entity = entity;
            this.accessToken = SecurityHelper.randomStringToken();
            this.refreshToken = SecurityHelper.randomStringToken();
            this.expireMillis = 0;
            this.userEntityUUID = entity.uuid;
        }

        public void update(long expireMillis) {
            this.expireMillis = System.currentTimeMillis() + expireMillis;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            UserSessionEntity entity = (UserSessionEntity) o;
            return Objects.equals(uuid, entity.uuid);
        }

        @Override
        public int hashCode() {
            return Objects.hash(uuid);
        }

        @Override
        public String getID() {
            return uuid.toString();
        }

        @Override
        public User getUser() {
            return entity;
        }

        @Override
        public long getExpireIn() {
            return expireMillis;
        }
    }
}