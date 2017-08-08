package com.ltsllc.common.application;

import com.ltsllc.common.commadline.CommandLine;

/**
 * A command line application.
 */
abstract public class Application {
    abstract public CommandLine createCommandLine (String[] argv);

    private CommandLine commandLine;

    public Application (String[] argv) {
        CommandLine commandLine = createCommandLine(argv);
        setCommandLine(commandLine);
    }

    public CommandLine getCommandLine() {
        return commandLine;
    }

    public void setCommandLine(CommandLine commandLine) {
        this.commandLine = commandLine;
    }

    public void go () {
        getCommandLine().parse();
    }
}
