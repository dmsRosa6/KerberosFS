package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;

public class RequestAuthenticationMessage implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String clientId;
    private final String serviceId;
    private final String clientAddress;
    private final LocalDateTime timestamp;

    public RequestAuthenticationMessage(String clientId, String clientAddress, String serviceId, LocalDateTime timestamp) {
        this.clientId = clientId;
        this.serviceId = serviceId;
        this.clientAddress = clientAddress;
        this.timestamp = timestamp;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getClientAddress() {
        return this.clientAddress;
    }

    public String getServiceId() {
        return this.serviceId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return "RequestAuthenticationMessage{" +
                "clientId='" + clientId + '\'' +
                ", serviceId='" + serviceId + '\'' +
                ", clientAddress='" + clientAddress + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}