package pro.gravit.launchermodules.discordauthsystem.commands;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.events.RequestEvent;
import pro.gravit.launcher.events.request.AuthRequestEvent;
import pro.gravit.launcher.profiles.PlayerProfile;
import pro.gravit.launchermodules.discordauthsystem.DiscordAuthSystemModule;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.command.Command;
import pro.gravit.launchserver.socket.Client;

public class TestCommand extends Command {
    private final transient Logger logger = LogManager.getLogger();
    private final DiscordAuthSystemModule module;

    public TestCommand(LaunchServer server, DiscordAuthSystemModule module) {
        super(server);
        this.module = module;
    }

    @Override
    public String getArgsDescription() {
        return null;
    }

    @Override
    public String getUsageDescription() {
        return null;
    }

    @Override
    public void invoke(String... args) throws Exception {
        server.nettyServerSocketHandler.nettyServer.service.forEachActiveChannels((ch, ws) -> {
            logger.info("ws.getConnectUUID() ->");
            logger.info(ws.getConnectUUID());
        });
    }
}
