package dmsrosa.kerberosfs.messages;


import java.time.LocalDateTime;

import dmsrosa.kerberosfs.commands.CommandReturn;

public class ResponseServiceMessage implements java.io.Serializable {
    private final LocalDateTime issueTimeReturn;
    private final CommandReturn commandReturn;

    public ResponseServiceMessage(CommandReturn commandReturn, LocalDateTime issueTimeReturn) {
        this.issueTimeReturn = LocalDateTime.now();
        this.commandReturn = commandReturn;
    }
    
    public CommandReturn getCommandReturn() {
        return commandReturn;
    }

    public LocalDateTime getissueTimeReturn() {
        return issueTimeReturn;
    }
}