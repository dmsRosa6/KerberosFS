package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;

public class Authenticator implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private final String clientId;
    private final String clientAddress;
    private final LocalDateTime timestamp;
    private final Command command;

    public Authenticator(String clientId, String clientAddress, Command command) {
        this.clientId = clientId;
        this.clientAddress = clientAddress;
        timestamp = LocalDateTime.now();
        this.command = command;
    }

    public Authenticator(String clientId, String clientAddress) {
        this.clientId = clientId;
        this.clientAddress = clientAddress;
        timestamp = LocalDateTime.now();
        this.command = null;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public Command getCommand() {
        return command;
    }

    public boolean isValid(String userId, String userAddress) {
        return this.clientId.equals(userId) && this.clientAddress.equals(userAddress);
    }

    @Override
    public String toString() {
        return "Authenticator{" +
                "clientId='" + clientId + '\'' +
                ", clientAddress='" + clientAddress + '\'' +
                ", timestamp=" + timestamp +
                ", command=" + (command == null ? "null" : command.toString()) +
                '}';
    }
}
