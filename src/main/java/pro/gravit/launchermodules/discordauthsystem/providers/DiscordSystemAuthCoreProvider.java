package pro.gravit.launchermodules.discordauthsystem.providers;

import pro.gravit.launcher.ClientPermissions;
import pro.gravit.launcher.events.request.GetAvailabilityAuthRequestEvent;
import pro.gravit.launcher.request.auth.details.AuthWebViewDetails;
import pro.gravit.launchserver.auth.MySQLSourceConfig;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.request.auth.AuthRequest;
import pro.gravit.launchermodules.discordauthsystem.ModuleImpl;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthException;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportExit;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class DiscordSystemAuthCoreProvider extends AuthCoreProvider implements AuthSupportExit {
    private final transient Logger logger = LogManager.getLogger();
    private transient ModuleImpl module;
    public MySQLSourceConfig mySQLHolder;

    public String uuidColumn;
    public String usernameColumn;
    public String accessTokenColumn;
    public String refreshTokenColumn;
    public String expiresInColumn;
    public String discordIdColumn;
    public String bannedAtColumn;
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
        if (refreshTokenColumn == null) logger.error("refreshTokenColumn cannot be null");
        if (expiresInColumn == null) logger.error("expiresInColumn cannot be null");
        if (discordIdColumn == null) logger.error("discordIdColumn cannot be null");
        if (bannedAtColumn == null) logger.error("bannedAtColumn cannot be null");
        if (table == null) logger.error("table cannot be null");

        String userInfoCols = String.format("%s, %s, %s, %s, %s, %s, %s", uuidColumn, usernameColumn, accessTokenColumn, refreshTokenColumn, expiresInColumn, discordIdColumn, bannedAtColumn);

        queryByUsernameSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, usernameColumn);

        queryByUUIDSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, uuidColumn);

        queryByAccessTokenSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, accessTokenColumn);

        queryByDiscordIdSQL = String.format("SELECT %s FROM %s WHERE %s=? LIMIT 1",
                userInfoCols, table, discordIdColumn);

        insertNewUserSQL = String.format("INSERT INTO %s (%s) VALUES (?, ?, ?, ?, ?, ?, ?)", table, userInfoCols);
    }

    @Override
    public User getUserByUsername(String username) {
        return getDiscordUserByUsername(username);
    }

    public DiscordUser getDiscordUserByUsername(String username) {
        try {
            return query(queryByUsernameSQL, username);
        } catch (IOException e) {
            logger.error("SQL error", e);
            return null;
        }
    }

    public DiscordUser updateDataUser(String discordId, String accessToken, String refreshToken, Long expiresIn) {
        try (Connection connection = mySQLHolder.getConnection()) {
            return updateDataUser(connection, discordId, accessToken, refreshToken, expiresIn);
        } catch (SQLException e) {
            logger.error("updateDataUser SQL error", e);
            return null;
        }
    }

    private DiscordUser updateDataUser(Connection connection, String discordId, String accessToken, String refreshToken, Long expiresIn) throws SQLException {

        ArrayList<String> setList = new ArrayList<String>();

        if (accessToken != null) {
            if (accessToken.length() == 0) {
                setList.add(accessTokenColumn + " = " + null);
            } else {
                setList.add(accessTokenColumn + " = '" + accessToken + "'");
            }
        }

        if (refreshToken != null) {
            if (refreshToken.length() == 0) {
                setList.add(refreshTokenColumn + " = " + null);
            } else {
                setList.add(refreshTokenColumn + " = '" + refreshToken + "'");
            }
        }

        if (expiresIn != null) {
            if (expiresIn == 0) {
                setList.add(expiresInColumn + " = " + null);
            } else {
                setList.add(expiresInColumn + " = " + expiresIn);
            }
        }

        String sqlSet = String.join(", ", setList);

        if (sqlSet.length() != 0) {
            String sql = String.format("UPDATE %s SET %s WHERE %s = %s", table, sqlSet, discordIdColumn, discordId);
            PreparedStatement s = connection.prepareStatement(sql);
            s.executeUpdate();
        }

        return getUserByDiscordId(discordId);
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
            logger.error("getUserByUUID SQL error", e);
            return null;
        }
    }

    public DiscordUser getUserByAccessToken(String accessToken) {
        try {
            return query(queryByAccessTokenSQL, accessToken);
        } catch (IOException e) {
            logger.error("getUserByAccessToken SQL error", e);
            return null;
        }
    }

    public DiscordUser getUserByDiscordId(String discordId) {
        try {
            return query(queryByDiscordIdSQL, discordId);
        } catch (IOException e) {
            logger.error("getUserByDiscordId SQL error", e);
            return null;
        }
    }

    public DiscordUser createUser(String uuid, String username, String accessToken, String refreshToken, Long expiresIn,  String discordId) {
        try (Connection connection = mySQLHolder.getConnection()) {
            return createUser(connection, uuid, username, accessToken, refreshToken, expiresIn, discordId);
        } catch (SQLException e) {
            logger.error("createUser SQL error", e);
            return null;
        }
    }

    private DiscordUser createUser(Connection connection, String uuid, String username, String accessToken, String refreshToken, Long expiresIn,  String discordId) throws SQLException {
        PreparedStatement s = connection.prepareStatement(insertNewUserSQL);
        s.setString(1, uuid);
        s.setString(2, username);
        s.setString(3, accessToken);
        s.setString(4, refreshToken);
        s.setLong(5, expiresIn);
        s.setString(6, discordId);
        s.setDate(7, null);
        s.executeUpdate();
        return getUserByAccessToken(accessToken);
    }

    @Override
    public UserSession getUserSessionByOAuthAccessToken(String accessToken) throws OAuthAccessTokenExpired {
        DiscordUser user = getUserByAccessToken(accessToken);
        if (user == null) return null;
        return new DiscordUserSession(user, accessToken);
    }

    @Override
    public AuthManager.AuthReport refreshAccessToken(String refreshToken, AuthResponse.AuthContext context) {
        try {
            var response = DiscordApi.sendRefreshToken(refreshToken);
            if(response == null) {
                return null;
            }
            DiscordUser user = getUserByAccessToken(response.access_token);
            if (user != null) {
                updateDataUser(user.discordId, response.access_token, response.refresh_token, response.expires_in * 1000);
            }
            return AuthManager.AuthReport.ofOAuth(response.access_token, response.refresh_token, response.expires_in * 1000, null);
        } catch (IOException e) {
            logger.error("DiscordAuth refresh failed", e);
            return null;
        }
    }

    @Override
    public AuthManager.AuthReport authorize(String login, AuthResponse.AuthContext context, AuthRequest.AuthPasswordInterface password, boolean minecraftAccess) throws AuthException {
        if(login == null) {
            throw AuthException.userNotFound();
        }

        DiscordUser user = getDiscordUserByUsername(login);

        if (user == null) {
            return null;
        }

        if (user.accessToken == null) {
            return null;
        }

        DiscordUserSession session = new DiscordUserSession(user, user.accessToken);
        return AuthManager.AuthReport.ofOAuth(user.accessToken, user.refreshToken, user.expiresIn * 1000, session);
    }

    @Override
    public User checkServer(Client client, String username, String serverID) throws IOException {
        User user = getUserByUsername(username);
        if (user.getUsername().equals(username) && user.getServerId().equals(serverID)) {
            return user;
        }
        return null;
    }

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
        return exitUser(session.getUser());
    }

    @Override
    public boolean exitUser(User user) {
        DiscordUser discordUser = getUserByAccessToken(user.getAccessToken());
        if (discordUser == null) {
            return true;
        }
        return updateDataUser(discordUser.discordId, "", null, null) != null;
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
                        set.getString(refreshTokenColumn),
                        set.getLong(expiresInColumn),
                        set.getString(discordIdColumn),
                        set.getDate(bannedAtColumn)
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
        public String refreshToken;
        public Long expiresIn;
        public Date bannedAt;

        public DiscordUser(String username, UUID uuid, String accessToken, String refreshToken, Long expiresIn, String discordId, Date bannedAt) {
            this.username = username;
            this.uuid = uuid;
            this.discordId = discordId;
            this.accessToken = accessToken;
            this.expiresIn = expiresIn;
            this.bannedAt = bannedAt;
            this.refreshToken = refreshToken;
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

        public String getRefreshToken() {
            return refreshToken;
        }

        public Long getExpiresIn() {
            return expiresIn;
        }

        @Override
        public ClientPermissions getPermissions() {
            return permissions;
        }

        @Override
        public boolean isBanned() {
            return this.bannedAt != null;
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
}