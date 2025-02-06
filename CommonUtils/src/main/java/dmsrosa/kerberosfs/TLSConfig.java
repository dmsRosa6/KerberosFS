package dmsrosa.kerberosfs;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

final class TLSConfig {
    private static final String TLS_CONFIG_PATH = "/app/tls-config.properties";
    private static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    
    private final SSLContext sslContext;
    private final String[] enabledProtocols;
    private final String[] cipherSuites;
    private char[] truststorePassword;

    public TLSConfig(char[] truststorePassword){
        try {
            Properties props = loadTLSProperties();
            this.sslContext = createSSLContext();
            this.enabledProtocols = parseProtocols(props);
            this.cipherSuites = parseCipherSuites(props);
            this.truststorePassword = truststorePassword;
        } catch (GeneralSecurityException | IOException ex) {
            throw new RuntimeException("TLS configuration failed", ex);
        }
    }

    private Properties loadTLSProperties() throws IOException {
        Properties props = new Properties();
        try (InputStream is = new FileInputStream(TLS_CONFIG_PATH)) {
            props.load(is);
        }
        return props;
    }

    private SSLContext createSSLContext() throws GeneralSecurityException, IOException {
        // Load the truststore using a secure password mechanism.
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(is, truststorePassword);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }

    private String[] parseProtocols(Properties props) {
        String prot = props.getProperty("TLS-PROT-ENF", "TLSv1.2").trim();
        return prot.split("\\s+");
    }

    private String[] parseCipherSuites(Properties props) {
        String ciphers = props.getProperty("CIPHERSUITES", "").trim();
        if (ciphers.isEmpty()) {
            return null;
        }
        return ciphers.split("\\s*,\\s*"); // Split on comma, trimming whitespace.
    }

    // Getters for other components
    SSLContext getSSLContext() { return sslContext; }
    String[] getEnabledProtocols() { return enabledProtocols; }
    String[] getCipherSuites() { return cipherSuites; }
}
