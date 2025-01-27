package dmsrosa.kerberosfs.commands;


import java.io.Serial;
import java.util.Arrays;

public class CommandReturn implements java.io.Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Command command;
    private final byte[] payload;

    public CommandReturn(Command command, byte[] payload) {
        this.command = command;
        this.payload = payload;
    }

    public CommandReturn(Command command) {
        this.command = command;
        this.payload = new byte[0];
    }

    public Command getCommand() {
        return command;
    }

    public byte[] getPayload() {
        return payload;
    }

    @Override
    public String toString() {
        return "CommandReturn{" +
                "command=" + command +
                ", payload=" + (payload == null ? "null" : Arrays.toString(payload)) +
                '}';
    }
}