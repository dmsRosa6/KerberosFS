package dmsrosa.kerberosfs.messages;

import java.io.Serial;
import java.io.Serializable;

public class RequestTGSMessage implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
    private final String serviceId;
    private final byte[] encryptedTGT;
    private final byte[] encryptedAuthenticator;

    public RequestTGSMessage(String serviceId, byte[] encryptedTGT, byte[] encryptedAuthenticator) {
        this.serviceId = serviceId;
        this.encryptedTGT = encryptedTGT;
        this.encryptedAuthenticator = encryptedAuthenticator;
    }

    public String getServiceId() {
        return serviceId;
    }

    public byte[] getEncryptedTGT() {
        return encryptedTGT;
    }

    public byte[] getEncryptedAuthenticator() {
        return encryptedAuthenticator;
    }

}