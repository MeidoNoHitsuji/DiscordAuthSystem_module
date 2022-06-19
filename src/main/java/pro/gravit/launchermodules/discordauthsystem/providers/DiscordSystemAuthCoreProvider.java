package pro.gravit.launchermodules.discordauthsystem.providers;

import pro.gravit.launcher.ClientPermissions;
import pro.gravit.launcher.events.request.GetAvailabilityAuthRequestEvent;
import pro.gravit.launcher.request.auth.details.AuthWebViewDetails;
import pro.gravit.launchserver.auth.MySQLSourceConfig;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.request.auth.AuthRequest;
import pro.gravit.launchermodules.discordauthsystem.Config;
import pro.gravit.launchermodules.discordauthsystem.ModuleImpl;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthException;
import pro.gravit.launchserver.auth.core.MySQLCoreProvider;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportExit;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportRegistration;
import pro.gravit.launchserver.helper.HttpHelper;
import pro.gravit.launchserver.manangers.AuthManager;
import pro.gravit.launchserver.socket.Client;
import pro.gravit.launchserver.socket.response.auth.AuthResponse;
import pro.gravit.utils.helper.SecurityHelper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public class DiscordSystemAuthCoreProvider extends AuthCoreProvider implements AuthSupportExit {
    private final transient Logger logger = LogManager.getLogger();
    private transient final HttpClient client = HttpClient.newBuilder().build();
    private static ModuleImpl module;
    public MySQLSourceConfig mySQLHolder;

    public String uuidColumn;
    public String usernameColumn;
    public String accessTokenColumn;
    public String discordIdColumn;
    public String table;

    private transient String queryByUUIDSQL;
    private transient String queryByUsernameSQL;
    private transient String queryByAccessTokenSQL;
    private transient String queryByDiscordIdSQL;

    private transient String insertNewUserSQL;

    @Override
    public void init(LaunchServer server) {
        module = server.modulesManager.getModule(ModuleImpl.class);
        if (mySQLHolder == null) logger.error("mySQLHolder cannot be null");
        if (uuidColumn == null) logger.error("uuidColumn cannot be null");
        if (usernameColumn == null) logger.error("usernameColumn cannot be null");
        if (accessTokenColumn == null) logger.error("accessTokenColumn cannot be null");
        if (discordIdColumn == null) logger.error("discordIdColumn cannot be null");
        if (table == null) logger.error("table cannot be null");

        String userInfoCols = String.format("%s, %s, %s, %s", uuidColumn, usernameColumn, accessTokenColumn, discordIdColumn);

        queryByUsernameSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, usernameColumn);

        queryByUUIDSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, uuidColumn);

        queryByAccessTokenSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, accessTokenColumn);

        queryByDiscordIdSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, discordIdColumn);

        insertNewUserSQL = String.format("INSERT INTO %s (%s) VALUES (?, ?, ?, ?)", table, userInfoCols);

    }

    @Override
    public User getUserByUsername(String username) {
        try {
            return query(queryByUsernameSQL, username);
        } catch (IOException e) {
            logger.error("SQL error", e);
            return null;
        }
    }

    @Override
    public User getUserByLogin(String login) {
        return getUserByUsername(login);
    }

    @Override
    public User getUserByUUID(UUID uuid) {
        try {
            return query(queryByUUIDSQL, uuid.toString());
        } catch (IOException e) {
            logger.error("SQL error", e);
            return null;
        }
    }

    public DiscordUser getUserByAccessToken(String accessToken) {
        try {
            return query(queryByAccessTokenSQL, accessToken);
        } catch (IOException e) {
            logger.error("SQL error", e);
            return null;
        }
    }

    public DiscordUser getUserByDiscordId(String discordId) {
        try {
            return query(queryByDiscordIdSQL, discordId);
        } catch (IOException e) {
            logger.error("SQL error", e);
            return null;
        }
    }

    public void createUser(Connection connection, String uuid, String username, String accessToken, String discordId) throws SQLException {
        PreparedStatement s = connection.prepareStatement(insertNewUserSQL);
        s.setString(1, uuid);
        s.setString(2, username);
        s.setString(3, accessToken);
        s.setString(4, discordId);
        s.executeUpdate();
    }

    private DiscordRefreshTokenResponse sendRefreshAccessToken(String refreshToken) throws IOException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(String.format("%s/oauth2/token", module.config.discordApiEndpoint)))
                .POST(HttpHelper.jsonBodyPublisher(new DiscordRefreshTokenRequest(refreshToken)))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();
        var e = HttpHelper.send(client, request, new HttpHelper.BasicJsonHttpErrorHandler<>(DiscordRefreshTokenResponse.class));
        return e.getOrThrow();
    }

    //TODO: Дописать реквестер на отправку кода при авторизации (authorization_code)

    @Override
    public UserSession getUserSessionByOAuthAccessToken(String accessToken) throws OAuthAccessTokenExpired {
        DiscordUser user = getUserByAccessToken(accessToken);
        if (user == null) return null;
        return new DiscordUserSession(user, accessToken);
    }

    @Override
    public AuthManager.AuthReport refreshAccessToken(String refreshToken, AuthResponse.AuthContext context) {
        try {
            var response = sendRefreshAccessToken(refreshToken);
            if(response == null) {
                return null;
            }
            return AuthManager.AuthReport.ofOAuth("", "", 0, null); //TODO: Добавить сюда правильный параметры
        } catch (IOException e) {
            logger.error("DiscordAuth refresh failed", e);
            return null;
        }
    }

    @Override
    public AuthManager.AuthReport authorize(String login, AuthResponse.AuthContext context, AuthRequest.AuthPasswordInterface password, boolean minecraftAccess) throws IOException {
        if(login == null) {
            throw AuthException.userNotFound();
        }

        logger.info(login);
        logger.info(context);
        logger.info(password);
        logger.info(minecraftAccess);

        //TODO: Перенести код из createOAuthSession сюда

        return null;
    }

    @Override
    public User checkServer(Client client, String username, String serverID) throws IOException {
        logger.info(client);
        logger.info(username);
        User user = getUserByUsername(username);
        logger.info(user);
        if (user.getUsername().equals(username)) {
            return user;
        }
        return null;
    }

//    @Override
//    public PasswordVerifyReport verifyPassword(User user, AuthRequest.AuthPasswordInterface password) {
//        if (!(password instanceof AuthPlainPassword)) {
//            return PasswordVerifyReport.FAILED;
//        }
//        DiscordAuthSystemConfig config = module.jsonConfigurable.getConfig();
//        AuthPlainPassword plainPassword = (AuthPlainPassword) password;
//        if (DiscordAuthSystemModule.verifyPassword(user, plainPassword.password, config)) {
//            return PasswordVerifyReport.OK;
//        }
//        return PasswordVerifyReport.FAILED;
//    }

//    @Override
//    public AuthManager.AuthReport createOAuthSession(User user, AuthResponse.AuthContext context, PasswordVerifyReport report, boolean minecraftAccess) throws IOException {
//        DiscordAuthSystemConfig config = module.jsonConfigurable.getConfig();
//        DiscordAuthSystemModule.DiscordUserSession entity = new DiscordAuthSystemModule.DiscordUserSession((DiscordAuthSystemModule.DiscordUser) user);
//        module.addNewSession(entity);
//        if (config.oauthTokenExpire != 0) {
//            entity.update(config.oauthTokenExpire);
//        }
//        if (minecraftAccess) {
//            String minecraftAccessToken = SecurityHelper.randomStringToken();
//            ((DiscordAuthSystemModule.DiscordUser) user).accessToken = minecraftAccessToken;
//            return AuthManager.AuthReport.ofOAuthWithMinecraft(minecraftAccessToken, entity.accessToken, entity.refreshToken, config.oauthTokenExpire);
//        }
//        return AuthManager.AuthReport.ofOAuth(entity.accessToken, entity.refreshToken, config.oauthTokenExpire);
//    }

    @Override
    protected boolean updateServerID(User user, String serverID) throws IOException {
        DiscordUser entity = (DiscordUser) user;
        if (entity == null) return false;
        entity.serverId = serverID;
        return true;
    }

    @Override
    public void close() throws IOException {

    }

    @Override
    public boolean deleteSession(UserSession session) {
        return true; //TODO: Обнулять accessToken
//        return module.deleteSession((DiscordUserSession) session);
    }

    @Override
    public boolean exitUser(User user) {
        return true; //TODO: Обнулять accessToken
//        return module.exitUser((DiscordUser) user);
    }

    private DiscordUser query(String sql, String value) throws IOException {
        try (Connection c = mySQLHolder.getConnection()) {
            PreparedStatement s = c.prepareStatement(sql);
            s.setString(1, value);
            s.setQueryTimeout(MySQLSourceConfig.TIMEOUT);
            try (ResultSet set = s.executeQuery()) {
                return constructUser(set);
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    private DiscordUser constructUser(ResultSet set) throws SQLException {
        return set.next() ?
                new DiscordUser(
                        set.getString(usernameColumn),
                        UUID.fromString(set.getString(uuidColumn)),
                        set.getString(accessTokenColumn),
                        set.getString(discordIdColumn)
                )
                : null;
    }

    @Override
    public List<GetAvailabilityAuthRequestEvent.AuthAvailabilityDetails> getDetails(Client client) {
        String state = UUID.randomUUID().toString();
        client.setProperty("state", state);
        String responseType = "code";
        String[] scope = new String[]{ "identify", "guilds.join", "email" };
        String url = String.format("%s?response_type=%s&client_id=%s&scope=%s&state=%s&redirect_uri=%s&prompt=consent", module.config.discordAuthorizeUrl, responseType, module.config.clientId, String.join("%20", scope), state, module.config.redirectUrl);
        return List.of(new AuthWebViewDetails(url, "https://google.com", true, true));
    }

    public static class DiscordUser implements User {
        public String username;
        public String discordId;
        public UUID uuid;
        public ClientPermissions permissions;
        public String serverId;
        public String accessToken;

        public DiscordUser(String username, UUID uuid, String accessToken, String discordId) {
            this.username = username;
            this.uuid = uuid;
            this.discordId = discordId;
            this.accessToken = accessToken;
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

    public static class DiscordUserSession implements UserSession {
        private final String id;
        public transient DiscordUser user;
        public String accessToken;
        public long expireMillis;

        public DiscordUserSession(DiscordUser user, String accessToken) {
            this.id = SecurityHelper.randomStringToken();
            this.user = user;
            this.accessToken = accessToken;
        }

        @Override
        public String getID() {
            return id;
        }

        @Override
        public User getUser() {
            return user;
        }

        @Override
        public long getExpireIn() {
            return expireMillis;
        }
    }

    public record DiscordRefreshTokenResponse() {} //TODO: Передать параметры

    public static class DiscordOauthRequest {
        public String client_id;
        public String client_secret;
        public String grant_type;
        public DiscordOauthRequest () {
            this.client_id = module.config.clientId;
            this.client_secret = module.config.clientSecret;
        }
    }

    public static class DiscordRefreshTokenRequest extends DiscordOauthRequest {
        public String refresh_token;
        public DiscordRefreshTokenRequest(String refresh_token) {
            super();
            this.grant_type = "refresh_token";
            this.refresh_token = refresh_token;
        }
    }

}