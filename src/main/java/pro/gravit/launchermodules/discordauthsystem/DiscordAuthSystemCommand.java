package pro.gravit.launchermodules.discordauthsystem;

import pro.gravit.launchermodules.discordauthsystem.commands.TestCommand;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.command.Command;

public class DiscordAuthSystemCommand extends Command {
    private final DiscordAuthSystemModule module;

    public DiscordAuthSystemCommand(LaunchServer server, DiscordAuthSystemModule module) {
        super(server);
        this.module = module;
        this.childCommands.put("test", new TestCommand(server, module));
    }

    @Override
    public String getArgsDescription() {
        return "[subcommand]";
    }

    @Override
    public String getUsageDescription() {
        return "manage DiscordAuthSystem";
    }

    @Override
    public void invoke(String... args) throws Exception {
        invokeSubcommands(args);
    }
}
