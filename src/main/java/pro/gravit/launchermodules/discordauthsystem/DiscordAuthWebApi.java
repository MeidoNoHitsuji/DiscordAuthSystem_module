package pro.gravit.launchermodules.discordauthsystem;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LogEvent;
import pro.gravit.launcher.ClientPermissions;
import pro.gravit.launcher.events.RequestEvent;
import pro.gravit.launcher.events.request.AuthRequestEvent;
import pro.gravit.launcher.profiles.PlayerProfile;
import pro.gravit.launchermodules.discordauthsystem.providers.DiscordSystemAuthCoreProvider;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthProviderPair;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.launchserver.config.log4j.LogAppender;
import pro.gravit.launchserver.manangers.AuthManager;
import pro.gravit.launchserver.socket.Client;
import pro.gravit.launchserver.socket.NettyConnectContext;
import pro.gravit.launchserver.socket.handlers.NettyWebAPIHandler;
import pro.gravit.launchserver.socket.response.auth.AuthResponse;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public class DiscordAuthWebApi implements NettyWebAPIHandler.SimpleSeverletHandler {

    private final DiscordAuthSystemModule module;
    private final LaunchServer server;
    private transient final Logger logger = LogManager.getLogger();

    public DiscordAuthWebApi(DiscordAuthSystemModule module, LaunchServer server) {
        this.module = module;
        this.server = server;
    }

    @Override
    public void handle(ChannelHandlerContext ctx, FullHttpRequest msg, NettyConnectContext context) throws Exception {

        Map<String, String> params = getParamsFromUri(msg.uri());

        String state = params.get("state");

        if (state == null || state.isEmpty()) {
            sendHttpResponse(ctx, simpleResponse(HttpResponseStatus.NOT_FOUND, "Не найден параметр state"));
            return;
        }

        String username = "test";

        AuthProviderPair pair = null;

        for (AuthProviderPair _pair : server.config.auth.values()) {
            if (_pair.core.getClass() == DiscordSystemAuthCoreProvider.class) {
                pair = _pair;
            }
        }

        if (pair != null && pair.isUseCore()) {
            User user = pair.core.getUserByLogin(username);
            UUID uuid;
            if (user == null) {
                uuid = UUID.randomUUID();
            } else {
                uuid = user.getUUID();
            }
            String minecraftAccessToken;
            AuthRequestEvent.OAuthRequestEvent oauth;

            AuthManager.AuthReport report = pair.core.createOAuthSession(user, null, null, true);
            minecraftAccessToken = report.minecraftAccessToken;
            oauth = new AuthRequestEvent.OAuthRequestEvent(report.oauthAccessToken, report.oauthRefreshToken, report.oauthExpire);
            AuthProviderPair finalPair = pair;
            server.nettyServerSocketHandler.nettyServer.service.forEachActiveChannels((ch, ws) -> {

                Client client = ws.getClient();
                if (client == null) {return;}
                String wsState = client.getProperty("state");
                if (wsState == null || wsState.isEmpty() || !wsState.equals(state)) {return;}

                client.coreObject = user;
                client.sessionObject = report.session;
                server.authManager.internalAuth(client, AuthResponse.ConnectTypes.CLIENT, finalPair, username, uuid, ClientPermissions.DEFAULT, true);
                PlayerProfile playerProfile = server.authManager.getPlayerProfile(client);
                AuthRequestEvent request = new AuthRequestEvent(ClientPermissions.DEFAULT, playerProfile, minecraftAccessToken, null, null, oauth);
                request.requestUUID = RequestEvent.eventUUID;
                server.nettyServerSocketHandler.nettyServer.service.sendObject(ch, request);

            });

            SuccessCommandResponse response = new SuccessCommandResponse();
            response.data = params;
            sendHttpResponse(ctx, simpleJsonResponse(HttpResponseStatus.OK, new DiscordAuthResponse<>(response)));
        } else {
            throw new UnsupportedOperationException("Auth provider/handler not supported");
        }
    }

    public static class DiscordAuthResponse<T> {
        public String error;
        public T data;

        public DiscordAuthResponse(String error) {
            this.error = error;
        }

        public DiscordAuthResponse(T data) {
            this.data = data;
        }
    }

    public static class SuccessCommandResponse {
        public String test = "Hello World";
        public Object data;
    }
}
