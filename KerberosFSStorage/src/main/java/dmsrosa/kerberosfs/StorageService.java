package dmsrosa.kerberosfs;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.commands.Command;
import dmsrosa.kerberosfs.commands.CommandReturn;
import dmsrosa.kerberosfs.crypto.CryptoException;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.MessageStatus;
import dmsrosa.kerberosfs.messages.RequestServiceMessage;
import dmsrosa.kerberosfs.messages.ResponseServiceMessage;
import dmsrosa.kerberosfs.messages.ServiceGrantingTicket;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class StorageService {

    // Configuration constants
    private final String KEYSTORE_PATH = "/app/keystore.jks";
    private final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private final String TLS_VERSION = "TLSv1.2";
    private final int PORT = 8083;
    private final String TLS_CONF_PATH = "/app/tls-config.properties";
    private final String KEYS_CONF_PATH = "/app/crypto-config.properties";

    // Cryptographic constants
    private final int KEYSIZE = 256;
    private final String ALGORITHM = "AES";

    // Instance fields
    private SSLContext sslContext;
    private final Properties tlsConfig = new Properties();
    private final Properties cryptoConfig = new Properties();
    private FsManager fsManager;
    protected static final Logger logger = Logger.getLogger(StorageService.class.getName());

    // Constructor – performs initialization tasks.
    public StorageService() {
        initLogger();
        loadConfigs();
        initializeSSLContext();
    }

    /**
     * Starts the service: initializes the file system manager and begins listening
     * for connections.
     */
    public void run() {
        try {
            fsManager = new FsManager("fs");
            logger.info("FsManager initialized successfully.");
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to initialize FsManager", e);
            System.exit(1);
        }
        try (SSLServerSocket serverSocket = createServerSocket()) {
            logger.info("Storage service started on port " + PORT);
            acceptConnections(serverSocket);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start storage service", e);
            System.exit(1);
        }
    }

    // ----------------------- Configuration & Initialization
    // -----------------------

    private void loadConfigs() {
        try (FileInputStream tlsIn = new FileInputStream(TLS_CONF_PATH);
                FileInputStream keysIn = new FileInputStream(KEYS_CONF_PATH)) {
            tlsConfig.load(tlsIn);
            cryptoConfig.load(keysIn);
            logger.info("Configurations loaded from " + TLS_CONF_PATH + " and " + KEYS_CONF_PATH);
        } catch (IOException ex) {
            logger.log(Level.WARNING, "Error loading configuration: " + ex.getMessage(), ex);
        }
    }

    private void initLogger() {
        // Remove default handlers and set a simplified console formatter.
        Logger rootLogger = Logger.getLogger("");
        for (Handler h : rootLogger.getHandlers()) {
            rootLogger.removeHandler(h);
        }
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new SimpleFormatter() {
            private final String format = "[%1$tT] [%2$-7s] %3$s %n";

            @Override
            public synchronized String format(LogRecord lr) {
                return String.format(format,
                        new Date(lr.getMillis()),
                        lr.getLevel().getLocalizedName(),
                        lr.getMessage());
            }
        });
        logger.addHandler(handler);
        logger.setLevel(Level.INFO);
        logger.info("Logger initialized.");
    }

    private void initializeSSLContext() {
        try {
            logger.info("Initializing SSL context.");
            KeyStore ks = loadKeyStore();
            logger.info("Keystore loaded with " + ks.size() + " entries.");
            KeyStore ts = loadTrustStore();
            logger.info("Truststore loaded with " + ts.size() + " entries.");

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, getKeystorePassword());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

            logger.info("SSL context successfully initialized.");
        } catch (IOException | GeneralSecurityException e) {
            logger.log(Level.SEVERE, "SSL Context Initialization Failed", e);
            throw new RuntimeException(e);
        }
    }

    private KeyStore loadKeyStore() throws GeneralSecurityException, IOException {
        return loadStore(KEYSTORE_PATH, getKeystorePassword());
    }

    private KeyStore loadTrustStore() throws GeneralSecurityException, IOException {
        return loadStore(TRUSTSTORE_PATH, getTruststorePassword());
    }

    private KeyStore loadStore(String path, char[] password) throws GeneralSecurityException, IOException {
        try (InputStream is = new FileInputStream(path)) {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(is, password);
            return ks;
        }
    }

    private SSLServerSocket createServerSocket() throws IOException {
        SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(PORT);
        serverSocket.setEnabledProtocols(getTlsProtocols());
        String[] ciphers = getCipherSuites();
        if (ciphers != null && ciphers.length > 0 && !ciphers[0].isEmpty()) {
            serverSocket.setEnabledCipherSuites(ciphers);
        }
        serverSocket.setNeedClientAuth(needsClientAuth());
        logger.info("ServerSocket created with protocols: " + Arrays.toString(getTlsProtocols())
                + " and ciphers: " + Arrays.toString(getCipherSuites()));
        return serverSocket;
    }

    // ----------------------- Connection Handling -----------------------

    private void acceptConnections(SSLServerSocket serverSocket) {
        ExecutorService executor = Executors.newCachedThreadPool();
        logger.info("Ready to accept client connections.");
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                logger.info("Accepted connection from " + clientSocket.getRemoteSocketAddress());
                SocketStreams streams = new SocketStreams(clientSocket);
                executor.submit(() -> handleClientConnection(streams));
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error accepting client connection", e);
            }
        }
        executor.shutdown();
    }

    private void handleClientConnection(SocketStreams streams) {
        try (streams) {
            logger.info("Client connected: " + streams.getRemoteAddress());
            while (true) {
                try {
                    Wrapper request = (Wrapper) streams.getOIS().readObject();
                    if (request == null) {
                        logger.info("Client closed the connection.");
                        break;
                    }
                    logger.info("Received request: " + request);
                    processStorageRequest(request, streams.getOOS());
                } catch (EOFException e) {
                    logger.info("Client disconnected normally.");
                    break;
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error processing client request", e);
                    break;
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error handling client " + streams.getRemoteAddress(), e);
        }
    }

    // ----------------------- Request Processing -----------------------

    private void processStorageRequest(Wrapper request, ObjectOutputStream oos)
            throws CryptoException, InvalidAlgorithmParameterException {
        logger.info("Processing storage request, messageId: " + request.getMessageId());
        ServiceGrantingTicket sgt = null; // Declare outside to use in catch block if needed.
        try {
            // Deserialize the request message.
            RequestServiceMessage reqMsg = (RequestServiceMessage) RandomUtils.deserialize(request.getMessage());
            logger.info("Deserialized RequestServiceMessage.");

            // Retrieve the shared key from configuration.
            SecretKey key = CryptoStuff.getInstance()
                    .convertStringToSecretKey(cryptoConfig.getProperty("STORAGE_TGS_KEY"));
            logger.info("Converted shared key.");

            // Decrypt and deserialize the Service Granting Ticket (SGT).
            byte[] encryptedSgt = reqMsg.getEncryptedSGT();
            logger.info("Decrypting SGT (length: " + encryptedSgt.length + ").");
            byte[] sgtBytes = CryptoStuff.getInstance().decrypt(key, encryptedSgt);
            sgt = (ServiceGrantingTicket) RandomUtils.deserialize(sgtBytes);
            logger.info("Decrypted SGT. ClientId: " + sgt.getClientId());

            // Decrypt and deserialize the Authenticator.
            byte[] encryptedAuth = reqMsg.getAuthenticator();
            logger.info("Decrypting Authenticator (length: " + encryptedAuth.length + ").");
            byte[] authBytes = CryptoStuff.getInstance().decrypt(sgt.getKey(), encryptedAuth);
            Authenticator authenticator = (Authenticator) RandomUtils.deserialize(authBytes);
            logger.info("Decrypted Authenticator. Timestamp: " + authenticator.getTimestamp());

            // Validate the authenticator.
            if (!authenticator.isValid(sgt.getClientId(), sgt.getClientAddress())) {
                logger.warning("Invalid authenticator for client: " + sgt.getClientId());
                Wrapper errorWrapper = new Wrapper((byte) 4, null, request.getMessageId(),
                        MessageStatus.UNAUTHORIZED.getCode());
                oos.writeObject(errorWrapper);
                return;
            }

            Command command = sgt.getCommand();
            String userId = sgt.getClientId();
            String path = userId + command.getPath();
            logger.info("Executing command " + command.getCommand() + " for path: " + path);

            fsManager.ensureUserDirectory(userId);

            byte[] responseContent = null;
            int responseStatus = MessageStatus.OK_NO_CONTENT.getCode();

            switch (command.getCommand()) {
                case GET:
                    logger.info("Executing GET command.");
                    String fileContent = fsManager.readFile(path);
                    if (fileContent != null && !fileContent.isEmpty()) {
                        responseContent = fileContent.getBytes(StandardCharsets.UTF_8);
                        responseStatus = MessageStatus.OK.getCode();
                    } else {
                        responseContent = new byte[0];
                        responseStatus = MessageStatus.OK_NO_CONTENT.getCode();
                    }
                    break;
                case PUT:
                    logger.info("Executing PUT command.");
                    if (command.getPayload() == null) {
                        logger.warning("PUT command missing content for path: " + path);
                    } else {
                        fsManager.writeFile(path, command.getPayload());
                    }
                    responseContent = new byte[0];
                    responseStatus = MessageStatus.OK_NO_CONTENT.getCode();
                    break;
                case RM:
                    logger.info("Executing RM command.");
                    fsManager.deleteFile(path);
                    responseContent = new byte[0];
                    responseStatus = MessageStatus.OK_NO_CONTENT.getCode();
                    break;
                case LS:
                    logger.info("Executing LS command.");
                    List<String> files = fsManager.listFolder(path);
                    if (files != null && !files.isEmpty()) {
                        responseContent = String.join("\n", files).getBytes(StandardCharsets.UTF_8);
                        responseStatus = MessageStatus.OK.getCode();
                    } else {
                        responseContent = new byte[0];
                        responseStatus = MessageStatus.OK_NO_CONTENT.getCode();
                    }
                    break;
                case MKDIR:
                    logger.info("Executing MKDIR command.");
                    fsManager.mkdir(path);
                    responseContent = new byte[0];
                    responseStatus = MessageStatus.OK_NO_CONTENT.getCode();
                    break;
                default:
                    logger.warning("Unknown command: " + command.getCommand().name());
                    responseContent = ("Unknown command: " + command.getCommand().name()).getBytes(StandardCharsets.UTF_8);
                    responseStatus = MessageStatus.BAD_REQUEST.getCode();
            }

            // Build the normal response.
            ResponseServiceMessage responseMsg = new ResponseServiceMessage(new CommandReturn(command, responseContent),
                    null);
            byte[] serializedResponse = RandomUtils.serialize(responseMsg);
            byte[] encryptedResponse = CryptoStuff.getInstance().encrypt(sgt.getKey(), serializedResponse);
            Wrapper responseWrapper = new Wrapper((byte) 4, encryptedResponse, request.getMessageId(), responseStatus);
            oos.writeObject(responseWrapper);
            oos.flush();
            logger.info("Response sent for messageId: " + request.getMessageId());
        } catch (IOException | ClassNotFoundException ex) {
            logger.log(Level.WARNING, "Error processing storage request: " + ex.getMessage(), ex);
            // Attempt to send an encrypted error response if possible.
            if (sgt != null) {
                try {
                    String errorMessage = "Error processing request: " + ex.getMessage();
                    ResponseServiceMessage errorResponse = new ResponseServiceMessage(
                            new CommandReturn(null, errorMessage.getBytes(StandardCharsets.UTF_8)), null);
                    byte[] serializedError = RandomUtils.serialize(errorResponse);
                    byte[] encryptedError = CryptoStuff.getInstance().encrypt(sgt.getKey(), serializedError);
                    Wrapper errorWrapper = new Wrapper((byte) 4, encryptedError, request.getMessageId(),
                            MessageStatus.INTERNAL_SERVER_ERROR.getCode());
                    oos.writeObject(errorWrapper);
                    oos.flush();
                    logger.info("Error response sent for messageId: " + request.getMessageId());
                } catch (Exception inner) {
                    logger.log(Level.SEVERE, "Error sending error response: " + inner.getMessage(), inner);
                }
            }
        }
    }

    // ----------------------- Helper Methods -----------------------

    private String[] getTlsProtocols() {
        String protocols = tlsConfig.getProperty("TLS-PROT-ENF", "TLSv1.2");
        return protocols.split(",");
    }

    private String[] getCipherSuites() {
        String ciphers = tlsConfig.getProperty("CIPHERSUITES", "");
        return ciphers.isEmpty() ? new String[0] : ciphers.split(",");
    }

    private boolean needsClientAuth() {
        return "MUTUAL".equalsIgnoreCase(System.getProperty("TLS-AUTH", "NONE"));
    }

    private char[] getKeystorePassword() {
        return "py6IDOytDVeqGjG6eflXoQ==".toCharArray();
    }

    private char[] getTruststorePassword() {
        return "BNCc7MdZuBJJYJQuRVnjbA==".toCharArray();
    }

    // ----------------------- Inner Class: SocketStreams -----------------------

    /**
     * Wraps the SSLSocket with Object streams and performs the SSL handshake
     * immediately.
     */
    private class SocketStreams implements AutoCloseable {
        private final SSLSocket socket;
        private ObjectOutputStream oos;
        private ObjectInputStream ois;

        public SocketStreams(SSLSocket socket) throws IOException {
            this.socket = socket;
            socket.startHandshake();
            logger.fine("SSL handshake completed with " + socket.getRemoteSocketAddress());
        }

        public ObjectOutputStream getOOS() throws IOException {
            if (oos == null) {
                oos = new ObjectOutputStream(socket.getOutputStream());
                oos.flush();
                logger.fine("Output stream initialized for " + getRemoteAddress());
            }
            return oos;
        }

        public ObjectInputStream getOIS() throws IOException {
            if (ois == null) {
                ois = new ObjectInputStream(socket.getInputStream());
                logger.fine("Input stream initialized for " + getRemoteAddress());
            }
            return ois;
        }

        public String getRemoteAddress() {
            return socket.getRemoteSocketAddress().toString();
        }

        @Override
        public void close() {
            try {
                if (oos != null)
                    oos.close();
            } catch (Exception ex) {
                logger.fine("Error closing output stream: " + ex.getMessage());
            }
            try {
                if (ois != null)
                    ois.close();
            } catch (Exception ex) {
                logger.fine("Error closing input stream: " + ex.getMessage());
            }
            try {
                if (socket != null && !socket.isClosed())
                    socket.close();
            } catch (Exception ex) {
                logger.fine("Error closing socket: " + ex.getMessage());
            }
            logger.info("Closed connection with " + getRemoteAddress());
        }
    }

    // ----------------------- Main Method -----------------------

    public static void main(String[] args) {
        StorageService service = new StorageService();
        service.run();
    }
}
