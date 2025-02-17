package dmsrosa.kerberosfs;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.messages.Wrapper;

public class MainDispatcher {
    private static final Logger logger = Logger.getLogger(MainDispatcher.class.getName());
    private static SSLServerSocket serverSocket;
    private static SSLContext context;

    private static final Properties tlsConfig = new Properties();
    private static final String KEYSTORE_PATH = "/app/keystore.jks";
    private static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private static final String TLS_CONFIG = "/app/tls-config.properties";
    private static final int SERVER_PORT = 8080;
    private static final int REQUEST_TIMEOUT = 20000; // milliseconds

    private enum ModuleName {
        STORAGE, AUTHENTICATION, ACCESS_CONTROL
    }

    static {
        logger.info("Loading TLS configuration from " + TLS_CONFIG);
        loadTlsConfiguration();
    }

    public static void main(String[] args) {
        logger.info("Starting MainDispatcher server");
        try {
            context = createSSLContext();
            initServerSocket();
            logger.info("Server started on port " + SERVER_PORT);
            startServerLoop();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Server fatal error", e);
        }
    }

    private static void loadTlsConfiguration() {
        try (var input = new java.io.FileInputStream(TLS_CONFIG)) {
            tlsConfig.load(input);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load TLS configuration", e);
        }
    }

    private static void initServerSocket() throws IOException {
        SSLServerSocketFactory factory = context.getServerSocketFactory();
        serverSocket = (SSLServerSocket) factory.createServerSocket(SERVER_PORT);
        configureServerSocket(serverSocket);
    }

    private static SSLContext createSSLContext() throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (var ksIs = new java.io.FileInputStream(KEYSTORE_PATH)) {
            keyStore.load(ksIs, getKeystorePassword());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, getKeystorePassword());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (var tsIs = new java.io.FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(tsIs, getTruststorePassword());
        }
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance(getTlsVersion());
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    private static void configureServerSocket(SSLServerSocket serverSocket) {
        serverSocket.setEnabledProtocols(getEnabledProtocols());
        String[] ciphers = getCipherSuites();
        if (ciphers != null && ciphers.length > 0 && !ciphers[0].isEmpty()) {
            serverSocket.setEnabledCipherSuites(ciphers);
        }
        serverSocket.setNeedClientAuth(needsClientAuth());
    }

    private static void startServerLoop() {
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                // Set the read timeout on the accepted socket.
                clientSocket.setSoTimeout(REQUEST_TIMEOUT);
                // Handle the connection (on the same thread or spawn a new one if desired)
                handleClientConnection(new SocketStreams(clientSocket));
            } catch (IOException e) {
                logger.log(Level.WARNING, "Client connection error", e);
            }
        }
    }

    /**
     * Loops on the connection's input stream to process multiple requests.
     */
    private static void handleClientConnection(SocketStreams clientStreams) {
        logger.info("New client connection from " + clientStreams.getRemoteAddress());
        try {
            while (true) {
                // Read the next request. With setSoTimeout, readObject() will throw SocketTimeoutException if no data arrives.
                Wrapper request = (Wrapper) clientStreams.getOIS().readObject();
                if (request == null) {
                    // End-of-stream reached.
                    logger.info("Client closed connection (readObject returned null).");
                    break;
                }
                logger.info("Received request: " + request);
                processClientRequest(clientStreams, request);
            }
        } catch (SocketTimeoutException ste) {
            logger.warning("Socket read timed out, closing connection.");
        } catch (EOFException eof) {
            logger.info("EOF reached, closing connection.");
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Error processing request, closing connection.", e);
        } finally {
            clientStreams.close();
        }
    }

    /**
     * Processes a single request. This method forwards the request to the target module and returns the response.
     */
    private static void processClientRequest(SocketStreams clientStreams, Wrapper request) {
        try {
            ModuleName targetModule = resolveTargetModule(request);
            try (SocketStreams moduleStreams = new SocketStreams(createModuleSocket(targetModule))) {
                logger.info("Forwarding request to: " + targetModule);
                moduleStreams.getOOS().writeObject(request);
                moduleStreams.getOOS().flush();

                logger.info("Waiting for module response...");
                Wrapper response = (Wrapper) moduleStreams.getOIS().readObject();
                logger.info("Module response: " + response);

                clientStreams.getOOS().writeObject(response);
                clientStreams.getOOS().flush();
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error in processing client request", e);
        }
    }

    private static ModuleName resolveTargetModule(Wrapper request) {
        switch (request.getMessageType()) {
            case 0:
            case 1:
                return ModuleName.AUTHENTICATION;
            case 2:
                return ModuleName.ACCESS_CONTROL;
            case 3:
                return ModuleName.STORAGE;
            default:
                throw new IllegalArgumentException("Invalid message type: " + request.getMessageType());
        }
    }

    private static SSLSocket createModuleSocket(ModuleName module) throws IOException {
        SSLSocketFactory factory = context.getSocketFactory();
        String[] hostPort = getModuleAddress(module);
        SocketAddress address = new InetSocketAddress(hostPort[0], Integer.parseInt(hostPort[1]));

        SSLSocket moduleSocket = (SSLSocket) factory.createSocket();
        moduleSocket.setEnabledProtocols(getEnabledProtocols());
        String[] ciphers = getCipherSuites();
        if (ciphers != null && ciphers.length > 0 && !ciphers[0].isEmpty()) {
            moduleSocket.setEnabledCipherSuites(ciphers);
        }
        moduleSocket.connect(address, 5000);
        moduleSocket.startHandshake();
        return moduleSocket;
    }

    private static String[] getModuleAddress(ModuleName module) {
        return tlsConfig.getProperty(module.toString()).split(":");
    }

    private static String[] getEnabledProtocols() {
        return tlsConfig.getProperty("TLS-PROT-ENF", "TLSv1.2").split(",");
    }

    private static String[] getCipherSuites() {
        String ciphers = tlsConfig.getProperty("CIPHERSUITES", "");
        return ciphers.isEmpty() ? new String[0] : ciphers.split(",");
    }

    private static boolean needsClientAuth() {
        return "MUTUAL".equalsIgnoreCase(tlsConfig.getProperty("TLS-AUTH-CLI", "NONE"));
    }

    private static char[] getKeystorePassword() {
        return "dbrCOv9mnfR22RqlM6HbmA==".toCharArray();
    }

    private static char[] getTruststorePassword() {
        return "Eod62hGNQNLEgqTIadv93w==".toCharArray();
    }

    private static String getTlsVersion() {
        return tlsConfig.getProperty("TLS_VERSION", "TLSv1.2");
    }

    /**
     * SocketStreams encapsulates the ObjectInputStream and ObjectOutputStream for a given SSLSocket.
     * It ensures the streams are created only once and provides helper methods.
     */
    private static class SocketStreams implements AutoCloseable {
        private SSLSocket socket;
        private ObjectOutputStream oos;
        private ObjectInputStream ois;

        SocketStreams(SSLSocket socket) {
            this.socket = socket;
            try {
                // Start the handshake immediately.
                socket.startHandshake();
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error during handshake", e);
            }
        }

        public ObjectOutputStream getOOS() throws IOException {
            if (oos == null) {
                oos = new ObjectOutputStream(socket.getOutputStream());
                oos.flush(); // flush header immediately
            }
            return oos;
        }

        public ObjectInputStream getOIS() throws IOException {
            if (ois == null) {
                ois = new ObjectInputStream(socket.getInputStream());
            }
            return ois;
        }

        public SSLSocket getSocket() {
            return socket;
        }

        public String getRemoteAddress() {
            return socket.getRemoteSocketAddress().toString();
        }

        @Override
        public void close() {
            try { if (oos != null) oos.close(); } catch (Exception ignored) { }
            try { if (ois != null) ois.close(); } catch (Exception ignored) { }
            try { if (socket != null && !socket.isClosed()) socket.close(); } catch (Exception ignored) { }
        }
    }
}
