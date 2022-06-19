package pro.gravit.launchermodules.discordauthsystem;

import java.util.HashMap;
import java.util.Map;

public class Config {
    public String clientId = "clientId";
    public String clientSecret = "clientSecret";
    public String discordAuthorizeUrl = "https://discord.com/oauth2/authorize";
    public String discordApiEndpoint = "https://discord.com/api/v8";
    public String redirectUrl = "redirectUrl";
    public long oauthTokenExpire = 60 * 60 * 1000;
}