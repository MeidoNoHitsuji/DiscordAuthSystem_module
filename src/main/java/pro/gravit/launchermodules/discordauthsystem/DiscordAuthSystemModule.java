package pro.gravit.launchermodules.discordauthsystem;

import pro.gravit.launcher.modules.LauncherModule;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.utils.Version;
import pro.gravit.utils.helper.IOHelper;
import pro.gravit.utils.helper.LogHelper;
import pro.gravit.utils.helper.SecurityHelper;

public class DiscordAuthSystemModule extends LauncherModule {
    public static final Version version = new Version(1, 0, 0, 0, Version.Type.LTS);
    
    public DiscordAuthSystemModule() {
        super(new LauncherModuleInfo("DiscordAuthSystem", version, new String[]{"LaunchServerCore"}));
    }

    public UserEntity getUser(String username) {
        return 'test';
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