package pro.gravit.launchermodules.discordauthsystem.providers;

import io.netty.buffer.Unpooled;
import pro.gravit.launcher.Launcher;
import pro.gravit.launcher.events.request.GetAvailabilityAuthRequestEvent;
import pro.gravit.launcher.request.auth.details.AuthPasswordDetails;
import pro.gravit.launcher.request.auth.details.AuthWebViewDetails;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.request.auth.AuthRequest;
import pro.gravit.launcher.request.auth.password.AuthPlainPassword;
import pro.gravit.launchermodules.discordauthsystem.DiscordAuthSystemConfig;
import pro.gravit.launchermodules.discordauthsystem.DiscordAuthSystemModule;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthException;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportExit;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportRegistration;
import pro.gravit.launchserver.manangers.AuthManager;
import pro.gravit.launchserver.socket.Client;
import pro.gravit.launchserver.socket.response.auth.AuthResponse;
import pro.gravit.utils.helper.IOHelper;
import pro.gravit.utils.helper.SecurityHelper;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class DiscordSystemAuthCoreProvider extends AuthCoreProvider implements AuthSupportRegistration, AuthSupportExit {
    private final transient Logger logger = LogManager.getLogger();
    private transient DiscordAuthSystemModule module;

    @Override
    public User getUserByUsername(String username) {
        return module.getUserByUsername(username);
    }

    @Override
    public User getUserByLogin(String login) {
        return module.getUserByLogin(login);
    }

    @Override
    public User getUserByUUID(UUID uuid) {
        return module.getUserByUUID(uuid);
    }

    @Override
    public void init(LaunchServer server) {
        module = server.modulesManager.getModule(DiscordAuthSystemModule.class);
    }

    @Override
    public UserSession getUserSessionByOAuthAccessToken(String accessToken) throws OAuthAccessTokenExpired {
        return null;
    }

    @Override
    public AuthManager.AuthReport refreshAccessToken(String refreshToken, AuthResponse.AuthContext context) {
        return null;
    }

    @Override
    public void verifyAuth(AuthResponse.AuthContext context) throws AuthException {
        // None
    }

    @Override
    public PasswordVerifyReport verifyPassword(User user, AuthRequest.AuthPasswordInterface password) {
        return PasswordVerifyReport.OK;
    }

    @Override
    public AuthManager.AuthReport createOAuthSession(User user, AuthResponse.AuthContext context, PasswordVerifyReport report, boolean minecraftAccess) throws IOException {
        if (minecraftAccess) {
            String minecraftAccessToken = SecurityHelper.randomStringToken();
            updateAuth(user, minecraftAccessToken);
            return AuthManager.AuthReport.ofMinecraftAccessToken(minecraftAccessToken);
        } else {
            return AuthManager.AuthReport.ofMinecraftAccessToken(null);
        }
    }

    public void updateAuth(User user, String minecraftAccessToken) {

    }

    @Override
    protected boolean updateServerID(User user, String serverID) throws IOException {
        return false;
    }

    @Override
    public void close() throws IOException {

    }

    @Override
    public User registration(String login, String email, AuthRequest.AuthPasswordInterface password, Map<String, String> properties) {
        return null;
    }

    @Override
    public boolean deleteSession(UserSession session) {
        return true;
    }

    @Override
    public boolean exitUser(User user) {
        return false;
    }

    @Override
    public List<GetAvailabilityAuthRequestEvent.AuthAvailabilityDetails> getDetails(Client client) {
        String state = UUID.randomUUID().toString();
        client.setProperty("state", state);
        String authorizeUrl = "https://discord.com/oauth2/authorize";
        String responseType = "code";
        String[] scope = new String[]{ "identify", "guilds.join", "email" };
        String url = String.format("%s?response_type=%s&client_id=%s&scope=%s&state=%s&redirect_uri=%s&prompt=consent", authorizeUrl, responseType, module.config.clientId, String.join("%20", scope), state, module.config.redirectUrl);
        return List.of(new AuthWebViewDetails(url, "https://google.com", true, true));
    }
}