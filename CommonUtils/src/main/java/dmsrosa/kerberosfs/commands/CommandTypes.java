package dmsrosa.kerberosfs.commands;

public enum CommandTypes {
    HELP(0),
    LOGIN(2),
    LS(2), 
    MKDIR(2),
    PUT(2),
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
}