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
import pro.gravit.launchserver.auth.MySQLSourceConfig;
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

public class ModuleImpl extends LauncherModule {
    public static final Version version = new Version(1, 0, 0, 0, Version.Type.LTS);
    private static final Gson gson = new Gson();
    public JsonConfigurable<Config> jsonConfigurable;

//    public Map<UUID, DiscordSystemAuthCoreProvider.DiscordUser> users = new ConcurrentHashMap<>();
//    public Set<DiscordSystemAuthCoreProvider.DiscordUserSession> sessions = ConcurrentHashMap.newKeySet();
    public Config config;
//    private Path dbPath;

    public ModuleImpl() {
        super(new LauncherModuleInfo("DiscordAuthSystem", version, new String[]{"LaunchServerCore"}));
    }

    @Override
    public void init(LauncherInitContext initContext) {
        registerEvent(this::finish, LaunchServerFullInitEvent.class);
//        registerEvent(this::preConfig, PreConfigPhase.class);
//        registerEvent(this::exit, ClosePhase.class);
        jsonConfigurable = modulesConfigManager.getConfigurable(Config.class, moduleInfo.name);
//        dbPath = modulesConfigManager.getModuleConfigDir(moduleInfo.name);
    }

    public void finish(LaunchServerFullInitEvent event) {
        LaunchServer launchServer = event.server;
        try {
            jsonConfigurable.loadConfig();
            config = jsonConfigurable.getConfig();
        } catch (IOException e) {
            LogHelper.error(e);
        }
//        load();
        NettyWebAPIHandler.addNewSeverlet("auth/discord", new WebApi(this, launchServer));
    }

//    public void exit(ClosePhase closePhase) {
//        if (jsonConfigurable != null && jsonConfigurable.getConfig() != null)
//            save();
//    }
//
//    public void load() {
//        load(dbPath);
//    }
//
//    public void load(Path path) {
//        {
//            Path sessionsPath = path.resolve("Sessions.json");
//            if (!Files.exists(sessionsPath)) return;
//            Type sessionsType = new TypeToken<Set<DiscordSystemAuthCoreProvider.DiscordUserSession>>() {
//            }.getType();
//            try (Reader reader = IOHelper.newReader(sessionsPath)) {
//                this.sessions = Launcher.gsonManager.configGson.fromJson(reader, sessionsType);
//            } catch (IOException e) {
//                LogHelper.error(e);
//            }
//            for (DiscordSystemAuthCoreProvider.DiscordUserSession sessionEntity : sessions) {
//                if (sessionEntity.userEntityUUID != null) {
//                    sessionEntity.user = getUserByUUID(sessionEntity.userEntityUUID);
//                }
//            }
//        }
//    }
//
//    public void save() {
//        save(dbPath);
//    }
//
//    public void save(Path path) {
//        {
//            Path sessionsPath = path.resolve("Sessions.json");
//            Type sessionsType = new TypeToken<Set<DiscordSystemAuthCoreProvider.DiscordUserSession>>() {
//            }.getType();
//            try (Writer writer = IOHelper.newWriter(sessionsPath)) {
//                Launcher.gsonManager.configGson.toJson(sessions, sessionsType, writer);
//            } catch (IOException e) {
//                LogHelper.error(e);
//            }
//        }
//    }
//
//    public void preConfig(PreConfigPhase preConfigPhase) {
//        AuthCoreProvider.providers.register("discordauthsystem", DiscordSystemAuthCoreProvider.class);
//    }

//    public DiscordSystemAuthCoreProvider.DiscordUser getUser(JoinServerRequest request) {
//        JsonElement responseUsername;
//        JsonElement responseUUID;
//        request.parameters = config.addParameters;
//        try {
//            JsonElement r = HTTPRequest.jsonRequest(gson.toJsonTree(request), new URL(config.backendUserUrl));
//            if (r == null) {
//                return null;
//            }
//            JsonObject response = r.getAsJsonObject();
//            responseUsername = response.get("username");
//            responseUUID = response.get("uuid");
//        } catch (IllegalStateException | IOException ignore) {
//            return null;
//        }
//        if (responseUsername != null && responseUUID != null) {
//            return new DiscordSystemAuthCoreProvider.DiscordUser(responseUsername.getAsString(), UUID.fromString(responseUUID.getAsString()));
//        } else {
//            return null;
//        }
//    }

//    public DiscordSystemAuthCoreProvider.DiscordUserSession getSessionByAccessToken(String accessToken) {
//        return sessions.stream().filter(e -> e.accessToken != null && e.accessToken.equals(accessToken)).findFirst().orElse(null);
//    }

//    public DiscordSystemAuthCoreProvider.DiscordUserSession getSessionByRefreshToken(String refreshToken) {
//        return sessions.stream().filter(e -> e.accessToken != null && e.refreshToken.equals(refreshToken)).findFirst().orElse(null);
//    }

//    public boolean deleteSession(DiscordSystemAuthCoreProvider.DiscordUserSession entity) {
//        return sessions.remove(entity);
//    }

//    public boolean exitUser(DiscordSystemAuthCoreProvider.DiscordUser user) {
//        return sessions.removeIf(e -> e.user == user);
//    }
}