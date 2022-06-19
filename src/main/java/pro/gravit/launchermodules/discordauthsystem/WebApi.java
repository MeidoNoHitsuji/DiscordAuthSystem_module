package pro.gravit.launchermodules.discordauthsystem;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.ClientPermissions;
import pro.gravit.launcher.events.RequestEvent;
import pro.gravit.launcher.events.request.AuthRequestEvent;
import pro.gravit.launcher.profiles.PlayerProfile;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthProviderPair;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.manangers.AuthManager;
import pro.gravit.launchserver.socket.Client;
import pro.gravit.launchserver.socket.NettyConnectContext;
import pro.gravit.launchserver.socket.handlers.NettyWebAPIHandler;
import pro.gravit.launchserver.socket.response.auth.AuthResponse;

import java.util.Map;
import java.util.UUID;

public class WebApi implements NettyWebAPIHandler.SimpleSeverletHandler {

    private final ModuleImpl module;
    private final LaunchServer server;
    private transient final Logger logger = LogManager.getLogger();

    public WebApi(ModuleImpl module, LaunchServer server) {
        this.module = module;
        this.server = server;
    }

    @Override
    public void handle(ChannelHandlerContext ctx, FullHttpRequest msg, NettyConnectContext context) throws Exception {
        //TODO: Переписать этот блок под новую реализацию
        Map<String, String> params = getParamsFromUri(msg.uri());

        String state = params.get("state");

        if (state == null || state.isEmpty()) {
            sendHttpResponse(ctx, simpleResponse(HttpResponseStatus.NOT_FOUND, "Не найден параметр state"));
            return;
        }

        String userUuid = params.get("uuid");

        if (userUuid == null || userUuid.isEmpty()) {
            sendHttpResponse(ctx, simpleResponse(HttpResponseStatus.NOT_FOUND, "Не найден параметр uuid"));
            return;
        }

        UUID uuid = UUID.fromString(userUuid);

        AuthProviderPair pair = server.config.getAuthProviderPair("discordauthsystem");;

        if (pair == null) {
            throw new UnsupportedOperationException("Auth provider/handler not supported");
        }

        User user = pair.core.getUserByUUID(uuid);
        if (user == null) {
            sendHttpResponse(ctx, simpleResponse(HttpResponseStatus.NOT_FOUND, "Пользователь с таким uuid не найден"));
            return;
        }
        if (user.isBanned()) {
            sendHttpResponse(ctx, simpleResponse(HttpResponseStatus.FORBIDDEN, "Вы были забанены!"));
            return;
        }
        String minecraftAccessToken;
        AuthRequestEvent.OAuthRequestEvent oauth;

        AuthManager.AuthReport report = pair.core.authorize(user, null, null, true);
        minecraftAccessToken = report.minecraftAccessToken();
        oauth = new AuthRequestEvent.OAuthRequestEvent(report.oauthAccessToken(), report.oauthRefreshToken(), report.oauthExpire());
        server.nettyServerSocketHandler.nettyServer.service.forEachActiveChannels((ch, ws) -> {

            Client client = ws.getClient();
            if (client == null) {
                return;
            }
            String wsState = client.getProperty("state");
            if (wsState == null || wsState.isEmpty() || !wsState.equals(state)) {
                return;
            }

            client.coreObject = user;
            client.sessionObject = report.session();
            server.authManager.internalAuth(client, AuthResponse.ConnectTypes.CLIENT, pair, user.getUsername(), uuid, ClientPermissions.DEFAULT, true);
            PlayerProfile playerProfile = server.authManager.getPlayerProfile(client);
            AuthRequestEvent request = new AuthRequestEvent(ClientPermissions.DEFAULT, playerProfile, minecraftAccessToken, null, null, oauth);
            request.requestUUID = RequestEvent.eventUUID;
            server.nettyServerSocketHandler.nettyServer.service.sendObject(ch, request);
        });
        sendHttpResponse(ctx, simpleResponse(HttpResponseStatus.OK, "Вы успешно авторизованы! Вернитесь, пожалуйста в лаунчер."));
    }
}
