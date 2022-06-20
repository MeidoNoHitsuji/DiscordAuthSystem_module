package pro.gravit.launchermodules.discordauthsystem.providers;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.Launcher;
import pro.gravit.launchermodules.discordauthsystem.Config;
import pro.gravit.launchserver.helper.HttpHelper;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class DiscordApi {
    private static HttpClient client;
    private static Gson gson;
    private static Config config;
    private static Logger logger;

    public static void initialize(Config config) {
        DiscordApi.config = config;
        DiscordApi.gson = new Gson();
        DiscordApi.logger = LogManager.getLogger();
        DiscordApi.client = HttpClient.newBuilder().build();
    }

    public static DiscordAccessTokenResponse sendRefreshToken(String refreshToken) throws IOException {
        var requestData = new DiscordRefreshTokenRequest(refreshToken);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(String.format("%s/oauth2/token?%s", config.discordApiEndpointVersion, requestData.ToUri())))
                .POST(HttpRequest.BodyPublishers.noBody())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();
        var e = HttpHelper.send(client, request, new HttpHelper.BasicJsonHttpErrorHandler<>(DiscordAccessTokenResponse.class));
        return e.getOrThrow();
    }

//    public static DiscordAccessTokenResponse getAccessTokenByCode(String code) {
//        try {
//            var request = gson.toJsonTree(new DiscordAccessTokenRequest(code));
//            logger.info(request);
//            JsonElement r = HTTPRequest.jsonRequest(request, new URL(String.format("%s/oauth2/token", config.discordApiEndpointV8)));
//            if (r == null) {
//                return null;
//            }
//            JsonObject response = r.getAsJsonObject();
//            logger.info(response);
//            return new DiscordAccessTokenResponse(
//                    response.get("access_token").getAsString(),
//                    response.get("token_type").getAsString(),
//                    response.get("expires_in").getAsInt(),
//                    response.get("refresh_token").getAsString(),
//                    response.get("scope").getAsString()
//            );
//        } catch (IllegalStateException | IOException ignore) {
//            logger.info("getAccessTokenByCode error");
//            return null;
//        }
//    }

    //TODO: ОНО НЕ РАБОТЕАТ!!!!
    public static DiscordAccessTokenResponse getAccessTokenByCode(String code) throws IOException, InterruptedException {
        var requestData = new DiscordAccessTokenRequest(code);
        var url = URI.create(String.format("%s/oauth2/token?%s", config.discordApiEndpointVersion, requestData.ToUri()));
        logger.info(url);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(url)
                .POST(HttpRequest.BodyPublishers.noBody())
                .header("Content-Type", "application/x-www-form-urlencoded")
//                .header("Accept", "*/*")
//                .header("Accept-Encoding", "*")
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        logger.info(response.body());
        logger.info(response.statusCode());
        logger.info(response.headers());
        logger.info(response);
//        var e = HttpHelper.send(client, request, new DiscordErrorHandler<>(DiscordAccessTokenResponse.class));
        return new DiscordAccessTokenResponse("", "", 0, "", "");
    }

    public static OauthMeResponse getDiscordUserByAccessToken(String accessToken) throws IOException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(String.format("%s/oauth2/@me", config.discordApiEndpoint)))
                .GET()
                .header("Authorization", String.format("Bearer %s", accessToken))
                .build();
        var e = HttpHelper.send(client, request, new HttpHelper.BasicJsonHttpErrorHandler<>(OauthMeResponse.class));
        return e.getOrThrow();
    }

    public static class DiscordUserResponse {
        public String id;
        public String username;
        public String discriminator;
        public String avatar;
        public String verified;
        public String email;
        public Integer flags;
        public String banner;
        public Integer accent_color;
        public Integer premium_type;
        public Integer public_flags;

        public DiscordUserResponse(String id, String username, String discriminator, String avatar, String verified, String email, Integer flags, String banner, Integer accent_color, Integer premium_type, Integer public_flags) {
            this.id = id;
            this.username = username;
            this.discriminator = discriminator;
            this.avatar = avatar;
            this.verified = verified;
            this.email = email;
            this.flags = flags;
            this.banner = banner;
            this.accent_color = accent_color;
            this.premium_type = premium_type;
            this.public_flags = public_flags;
        }
    }

    public static class OauthMeResponse {
        public String[] scopes;
        public String expires;
        public DiscordUserResponse user;

        public OauthMeResponse(String[] scopes, String expires, DiscordUserResponse user) {
            this.scopes = scopes;
            this.expires = expires;
            this.user = user;
        }
    }

    public static class DiscordAccessTokenResponse {
        public String access_token;
        public String token_type;
        public long expires_in;
        public String refresh_token;
        public String scope;

        public DiscordAccessTokenResponse(String access_token, String token_type, long expires_in, String refresh_token, String scope) {
            this.access_token = access_token;
            this.token_type = token_type;
            this.expires_in = expires_in;
            this.refresh_token = refresh_token;
            this.scope = scope;
        }
    }

    public static class DiscordErrorResponse {
        public String error;
        public String error_description;

        public DiscordErrorResponse(String error, String error_description) {
            this.error = error;
            this.error_description = error_description;
        }
    }

    public static class DiscordOauthRequest {
        public String client_id;
        public String client_secret;
        public String grant_type;

        public DiscordOauthRequest() {
            this.client_id = config.clientId;
            this.client_secret = config.clientSecret;
        }

        public String ToUri() {
            return String.format("client_id=%s&client_secret=%s&grant_type=%s", this.client_id, this.client_secret, this.grant_type);
        }
    }

    public static class DiscordRefreshTokenRequest extends DiscordOauthRequest {
        public String refresh_token;

        public DiscordRefreshTokenRequest(String refresh_token) {
            super();
            this.grant_type = "refresh_token";
            this.refresh_token = refresh_token;
        }

        @Override
        public String ToUri() {
            return String.format("%s&refresh_token=%s", super.ToUri(), this.refresh_token);
        }
    }

    public static class DiscordAccessTokenRequest extends DiscordOauthRequest {
        public String code;
        public String redirect_uri;

        public DiscordAccessTokenRequest(String code) {
            super();
            this.grant_type = "authorization_code";
            this.redirect_uri = config.redirectUrl;
            this.code = code;
        }

        @Override
        public String ToUri() {
            return String.format("%s&code=%s&redirect_uri=%s", super.ToUri(), this.code, this.redirect_uri);
        }
    }

    private static class DiscordErrorHandler<T> implements HttpHelper.HttpJsonErrorHandler<T, DiscordErrorResponse> {

        private final Class<T> type;

        private DiscordErrorHandler(Class<T> type) {
            this.type = type;
        }

        @Override
        public HttpHelper.HttpOptional<T, DiscordErrorResponse> applyJson(JsonElement response, int statusCode) {
            logger.info(response);
            if(statusCode < 200 || statusCode >= 300) {
                return new HttpHelper.HttpOptional<>(null, Launcher.gsonManager.gson.fromJson(response, DiscordErrorResponse.class), statusCode);
            } else {
                return new HttpHelper.HttpOptional<>(Launcher.gsonManager.gson.fromJson(response, type), null, statusCode);
            }
        }

        @Override
        public HttpHelper.HttpOptional<T, DiscordErrorResponse> apply(HttpResponse<InputStream> response) {
            logger.info(response.body());
            try(Reader reader = new InputStreamReader(response.body())) {
                logger.info(reader);
//                var gsonBuilder = Launcher.gsonManager.gsonBuilder.setLenient();
//                var gson = gsonBuilder.create();
                var element = Launcher.gsonManager.gson.fromJson(reader, JsonElement.class);
                return applyJson(element, response.statusCode());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
