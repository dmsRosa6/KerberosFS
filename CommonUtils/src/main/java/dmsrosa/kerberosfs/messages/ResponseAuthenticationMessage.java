package dmsrosa.kerberosfs.messages;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;

import javax.crypto.SecretKey;

public class ResponseAuthenticationMessage implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final SecretKey generatedKey;
    private final LocalDateTime issueTime;
    private final Duration lifetime;
    private final byte[] encryptedTGT;

    public ResponseAuthenticationMessage(SecretKey generatedKey, byte[] encryptedTGT) {
        this.generatedKey = generatedKey;
        this.issueTime = LocalDateTime.now();
        this.lifetime = Duration.ofHours(8);
        this.encryptedTGT = encryptedTGT;
    }

    public LocalDateTime getIssueTime() {
        return issueTime;
    }

    public SecretKey getGeneratedKey() {
        return generatedKey;
    }

    public Duration getLifetime() {
        return lifetime;
    }

    public byte[] getEncryptedTGT() {
        return encryptedTGT;
    }
}