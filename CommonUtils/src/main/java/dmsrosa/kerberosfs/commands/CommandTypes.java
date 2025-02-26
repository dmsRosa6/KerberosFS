package dmsrosa.kerberosfs.commands;

import java.util.Optional;

public enum CommandTypes {
    HELP(0),
    LOGIN(2),
    LS(2),
    MKDIR(2),
    PUT(3),
    RM(2),
    FILE(2),
    CP(3),
    GET(2);

    private final int expectedArgs;

    CommandTypes(int expectedArgs) {
        this.expectedArgs = expectedArgs;
    }

    public int getExpectedArgs() {
        return expectedArgs;
    }

    public static Optional<CommandTypes> fromString(String command) {
        for (CommandTypes type : CommandTypes.values()) {
            if (type.name().equals(command.toUpperCase())) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }

    

}
