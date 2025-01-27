package dmsrosa.kerberosfs.messages;

import java.io.Serializable;

import dmsrosa.kerberosfs.commands.Command;

public class RequestServiceMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] encryptedSGT;
    private final byte[] authenticator;
    private final Command command;

    public RequestServiceMessage(byte[] encryptedSGT, byte[] authenticator, Command command) {
        this.encryptedSGT = encryptedSGT;
        this.authenticator = authenticator;
        this.command = command;
    }

    public Command getCommand() {
        return command;
    }

    public byte[] getEncryptedSGT() {
        return encryptedSGT;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}