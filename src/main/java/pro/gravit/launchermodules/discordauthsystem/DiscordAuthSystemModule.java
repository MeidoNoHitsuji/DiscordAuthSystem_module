package pro.gravit.launchermodules.discordauthsystem;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import pro.gravit.launcher.ClientPermissions;
import pro.gravit.launcher.HTTPRequest;
import pro.gravit.launcher.config.JsonConfigurable;
import pro.gravit.launcher.modules.LauncherInitContext;
import pro.gravit.launcher.modules.LauncherModule;
import pro.gravit.launcher.modules.LauncherModuleInfo;
import pro.gravit.launcher.modules.events.PreConfigPhase;
import pro.gravit.launchermodules.discordauthsystem.providers.DiscordSystemAuthCoreProvider;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.modules.events.LaunchServerFullInitEvent;
import pro.gravit.launchserver.socket.handlers.NettyWebAPIHandler;
import pro.gravit.utils.Version;
import pro.gravit.utils.helper.LogHelper;

import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.UUID;

public class DiscordAuthSystemModule extends LauncherModule {
    public static final Version version = new Version(1, 0, 0, 0, Version.Type.LTS);
    private static final Gson gson = new Gson();
    public JsonConfigurable<DiscordAuthSystemConfig> jsonConfigurable;
    public DiscordAuthSystemConfig config;

    public DiscordAuthSystemModule() {
        super(new LauncherModuleInfo("DiscordAuthSystem", version, new String[]{"LaunchServerCore"}));
    }

    @Override
    public void init(LauncherInitContext initContext) {
        registerEvent(this::finish, LaunchServerFullInitEvent.class);
        registerEvent(this::preConfig, PreConfigPhase.class);
        jsonConfigurable = modulesConfigManager.getConfigurable(DiscordAuthSystemConfig.class, moduleInfo.name);
    }

    public void finish(LaunchServerFullInitEvent event) {
        LaunchServer launchServer = event.server;
        try {
            jsonConfigurable.loadConfig();
            config = jsonConfigurable.getConfig();
        } catch (IOException e) {
            LogHelper.error(e);
        }
        NettyWebAPIHandler.addNewSeverlet("auth/discord", new DiscordAuthWebApi(this, launchServer));
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
}