package org.example.utils;

import java.io.Serializable;

public class RequestServiceMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] encryptedSGT;
    private final byte[] authenticator;

    public RequestServiceMessage(byte[] encryptedSGT, byte[] authenticator) {
        this.encryptedSGT = encryptedSGT;
        this.authenticator = authenticator;
    }

    public byte[] getEncryptedSGT() {
        return encryptedSGT;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}