package dmsrosa.kerberosfs;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.TimeoutUtils;

public class MainDispatcher {
    private static final Logger logger = Logger.getLogger(MainDispatcher.class.getName());
    private static final Map<UUID, SSLSocket> clientSocketMap = new ConcurrentHashMap<>();
    
    public enum ModuleName {
        STORAGE, AUTHENTICATION, ACCESS_CONTROL
    }

    // Configuration
    private static final Properties properties = new Properties();
    private static final String KEYSTORE_PATH = "/app/keystore.jks";
    private static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private static final String TLS_CONFIG = "/app/tls-config.properties";
    private static final int SERVER_PORT = 8080;
    private static final long REQUEST_TIMEOUT = 20000;
    
    static {
        loadTlsConfiguration();
    }

    public static void main(String[] args) {
        try {
            logger.info("Starting MainDispatcher server");
            initTLSServerSocket();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Fatal server error", e);
            System.exit(1);
        }
    }

    // Initialization methods
    private static void loadTlsConfiguration() {
        try (InputStream input = new FileInputStream(TLS_CONFIG)) {
            properties.load(input);
            logger.info("Loaded TLS configuration");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load TLS configuration", e);
        }
    }

    private static void initTLSServerSocket() {
        try (SSLServerSocket serverSocket = createSSLServerSocket()) {
            configureServerSocket(serverSocket);
            startServerLoop(serverSocket);
        } catch (IOException | GeneralSecurityException e) {
            logger.log(Level.SEVERE, "SSL server initialization failed", e);
            throw new RuntimeException("Server initialization failed", e);
        }
    }

    private static SSLServerSocket createSSLServerSocket() throws IOException, GeneralSecurityException {
        SSLContext sslContext = createSSLContext();
        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
        return (SSLServerSocket) socketFactory.createServerSocket(SERVER_PORT);
    }

    private static SSLContext createSSLContext() throws GeneralSecurityException, IOException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(loadKeyStore(), getKeystorePassword());
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(loadTrustStore());

        SSLContext sslContext = SSLContext.getInstance(getTlsVersion());
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    // Helper methods
    private static KeyStore loadKeyStore() throws GeneralSecurityException, IOException {
        return loadStore(KEYSTORE_PATH, getKeystorePassword());
    }

    private static KeyStore loadTrustStore() throws GeneralSecurityException, IOException {
        return loadStore(TRUSTSTORE_PATH, getTruststorePassword());
    }

    private static KeyStore loadStore(String path, char[] password) throws GeneralSecurityException, IOException {
        try (InputStream is = new FileInputStream(path)) {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(is, password);
            return ks;
        }
    }

    private static void configureServerSocket(SSLServerSocket serverSocket) {
        serverSocket.setEnabledProtocols(getEnabledProtocols());
        serverSocket.setEnabledCipherSuites(getCipherSuites());
        serverSocket.setNeedClientAuth(needsClientAuth());
        logger.info(() -> String.format("Server configured with protocols: %s, ciphers: %s",
                Arrays.toString(getEnabledProtocols()), Arrays.toString(getCipherSuites())));
    }

    // Server operations
    private static void startServerLoop(SSLServerSocket serverSocket) {
        logger.info(() -> "Server listening on port " + serverSocket.getLocalPort());
        
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                handleClientConnection(clientSocket);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error accepting client connection", e);
            }
        }
    }

   private static void handleClientConnection(SSLSocket clientSocket) {
        try {
            logger.info(() -> "New client connection from: " + clientSocket.getRemoteSocketAddress());
            clientSocket.startHandshake();

            TimeoutUtils.runWithTimeout(() -> {
                try (ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream())) {
                    Wrapper request = (Wrapper) ois.readObject();
                    processClientRequest(clientSocket, request);
                } catch (IOException | ClassNotFoundException e) {
                    logger.log(Level.WARNING, "Error processing client request", e);
                    throw new CompletionException("Request handling failed", e);
                }
            }, REQUEST_TIMEOUT);
            
        } catch (TimeoutException e) {
            logger.warning("Request processing timed out");
            sendErrorResponse(clientSocket, 504, "Gateway Timeout");
        } catch (CompletionException e) {
            logger.log(Level.WARNING, "Failed to process client request", e.getCause());
            sendErrorResponse(clientSocket, 500, "Internal Server Error");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Unexpected error handling client connection", e);
        } finally {
            closeSocketSilently(clientSocket);
            logger.info("Client connection closed");
        }
        }

        private static void sendErrorResponse(SSLSocket socket, int errorCode, String message) {
        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            oos.writeObject(new Wrapper((byte) errorCode, message.getBytes(), UUID.randomUUID()));
        } catch (IOException e) {
            logger.log(Level.FINE, "Failed to send error response", e);
        }
        }

    private static void processClientRequest(SSLSocket clientSocket, Wrapper request) {
        try {
            ModuleName targetModule = resolveTargetModule(request);
            logger.info(() -> String.format("Routing request %s to %s", request.getMessageId(), targetModule));
            
            try (SSLSocket moduleSocket = createModuleSocket(targetModule)) {
                forwardRequestToModule(request, moduleSocket);
                Wrapper response = receiveModuleResponse(moduleSocket);
                forwardResponseToClient(clientSocket, response);
            } catch (GeneralSecurityException ex) {
                logger.log(Level.WARNING, "Error fowarding message", ex);
            }
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Request processing failed", e);
            throw new RuntimeException("Request processing error", e);
        }
    }

    // Network operations
    private static SSLSocket createModuleSocket(ModuleName module) throws IOException, GeneralSecurityException {
        String[] address = getModuleAddress(module);
        SSLContext sslContext = createSSLContext();
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory()
                .createSocket(address[0], Integer.parseInt(address[1]));
        
        socket.setEnabledProtocols(getEnabledProtocols());
        socket.setEnabledCipherSuites(getCipherSuites());
        socket.startHandshake();
        return socket;
    }

    private static void forwardRequestToModule(Wrapper request, SSLSocket moduleSocket) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(moduleSocket.getOutputStream())) {
            oos.writeObject(request);
        }
    }

    private static Wrapper receiveModuleResponse(SSLSocket moduleSocket) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(moduleSocket.getInputStream())) {
            return (Wrapper) ois.readObject();
        }
    }

    private static void forwardResponseToClient(SSLSocket clientSocket, Wrapper response) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream())) {
            oos.writeObject(response);
        }
    }

    // Configuration getters
    private static String[] getEnabledProtocols() {
        return properties.getProperty("TLS-PROT-ENF", "TLSv1.2").split(",");
    }

    private static String[] getCipherSuites() {
        return properties.getProperty("CIPHERSUITES", "").split(",");
    }

    private static boolean needsClientAuth() {
        return "MUTUAL".equalsIgnoreCase(properties.getProperty("TLS-AUTH-SRV", "NONE"));
    }

    private static char[] getKeystorePassword() {
        return "dbrCOv9mnfR22RqlM6HbmA==".toCharArray();
    }

    private static char[] getTruststorePassword() {
        return "Eod62hGNQNLEgqTIadv93w==".toCharArray();
    }

    private static String getTlsVersion() {
        return properties.getProperty("TLS_VERSION", "TLSv1.2");
    }

    // Utility methods
    private static ModuleName resolveTargetModule(Wrapper request) {
        return switch (request.getMessageType()) {
            case 0, 1 -> ModuleName.AUTHENTICATION;
            case 3 -> ModuleName.ACCESS_CONTROL;
            case 6 -> ModuleName.STORAGE;
            default -> throw new IllegalArgumentException("Invalid message type: " + request.getMessageType());
        };
    }

    private static String[] getModuleAddress(ModuleName module) {
        return switch (module) {
            case STORAGE -> new String[]{"172.17.0.1", "8083"};
            case AUTHENTICATION -> new String[]{"172.17.0.1", "8081"};
            case ACCESS_CONTROL -> new String[]{"172.17.0.1", "8082"};
        };
    }

    private static void closeSocketSilently(SSLSocket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            logger.log(Level.FINEST, "Error closing socket", e);
        }
    }
}