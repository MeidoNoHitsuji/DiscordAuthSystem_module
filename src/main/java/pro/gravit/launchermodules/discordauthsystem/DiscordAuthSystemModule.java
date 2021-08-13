package pro.gravit.launchermodules.discordauthsystem;

import pro.gravit.launcher.ClientPermissions;
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
import java.util.Arrays;
import java.util.UUID;

public class DiscordAuthSystemModule extends LauncherModule {
    public static final Version version = new Version(1, 0, 0, 0, Version.Type.LTS);
    public JsonConfigurable<DiscordAuthSystemConfig> jsonConfigurable;

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
        } catch (IOException e) {
            LogHelper.error(e);
        }
        launchServer.commandHandler.registerCommand("discordauthsystem", new DiscordAuthSystemCommand(launchServer, this));
        NettyWebAPIHandler.addNewSeverlet("auth/discord", new DiscordAuthWebApi(this, launchServer));
    }

    public void preConfig(PreConfigPhase preConfigPhase) {
        AuthCoreProvider.providers.register("discordauthsystem", DiscordSystemAuthCoreProvider.class);
    }

    public UserEntity getUser(String username) {
        return new UserEntity("test");
    }

    public UserEntity getUser(UUID uuid) {
        return new UserEntity("test");
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
    }

    public static class UserEntity implements User {
        public String username;
        public UUID uuid;
        public ClientPermissions permissions;
        public String serverId;
        public String accessToken;
        private byte[] password;

        public UserEntity() {
            permissions = new ClientPermissions();
        }

        public UserEntity(String username) {
            this.username = username;
            this.uuid = UUID.randomUUID();
            this.permissions = new ClientPermissions();
        }

        public UserEntity(String username, String password) {
            this.username = username;
            this.uuid = UUID.randomUUID();
            this.permissions = new ClientPermissions();
            this.setPassword(password);
        }

        public void setPassword(String password) {
            this.password = SecurityHelper.digest(SecurityHelper.DigestAlgorithm.SHA256, password);
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

        public boolean verifyPassword(String password) {
            return Arrays.equals(this.password, SecurityHelper.digest(SecurityHelper.DigestAlgorithm.SHA256, password));
        }
    }
}