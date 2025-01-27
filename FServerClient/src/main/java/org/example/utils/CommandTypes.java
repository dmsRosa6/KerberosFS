package org.example.utils;

public enum CommandTypes {
    HELP(0),
    LOGIN(2),
    LS(0), 
    MKDIR(2),
    PUT(2),
    RM(2),
    FILE(2),
    CP(2),
    GET(1);     

    private final int expectedArgs;

    CommandTypes(int expectedArgs) {
        this.expectedArgs = expectedArgs;
    }

    public int getExpectedArgs() {
        return expectedArgs;
    }
}