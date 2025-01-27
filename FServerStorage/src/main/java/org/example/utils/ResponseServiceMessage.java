package org.example.utils;

import java.time.LocalDateTime;

public class ResponseServiceMessage implements java.io.Serializable {
    private final LocalDateTime issueTimeReturn;
    private final CommandReturn commandReturn;

    public ResponseServiceMessage(CommandReturn commandReturn, LocalDateTime issueTimeReturn) {
        this.issueTimeReturn = LocalDateTime.now();
        this.commandReturn = commandReturn;
    }

    public CommandReturn getcommandReturn() {
        return commandReturn;
    }

    public LocalDateTime getissueTimeReturn() {
        return issueTimeReturn;
    }
}
