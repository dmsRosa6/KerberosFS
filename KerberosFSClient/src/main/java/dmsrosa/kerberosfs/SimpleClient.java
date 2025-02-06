package dmsrosa.kerberosfs;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SimpleClient {

    // Adjust these constants as needed.
    private static final String TRUSTSTORE_PATH = "/truststore.jks"; // Must be on the classpath (e.g., in src/main/resources)
    private static final String TRUSTSTORE_PASSWORD = "Y+kS81NkLbcUPXq3J2PPlg=="; // Replace with your truststore password
    private static final String TLS_VERSION = "TLSv1.2";
    private static final String HOST = "localhost";
    private static final int PORT = 8080;

    public static void main(String[] args) {
        try {
            SSLContext sslContext = createSSLContext();
            SSLSocketFactory factory = sslContext.getSocketFactory();

            Socket socket = factory.createSocket(HOST, PORT);
            
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            out.writeUTF("OLA");
            out.flush();
            
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        } catch (IOException ex) {
        }
    }

    private static SSLContext createSSLContext() throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, KeyManagementException {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream ts = SimpleClient.class.getResourceAsStream(TRUSTSTORE_PATH)) {
            if (ts == null) {
                throw new RuntimeException("Truststore not found in classpath: " + TRUSTSTORE_PATH);
            }
            trustStore.load(ts, TRUSTSTORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }
}
