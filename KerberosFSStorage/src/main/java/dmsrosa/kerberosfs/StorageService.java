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
import java.util.UUID;
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
import dmsrosa.kerberosfs.messages.FilePayload;
import dmsrosa.kerberosfs.messages.RequestServiceMessage;
import dmsrosa.kerberosfs.messages.ResponseServiceMessage;
import dmsrosa.kerberosfs.messages.ServiceGrantingTicket;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class StorageService {

    // Configuration constants
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT = 8083;
    private static final String TLS_CONF_PATH = "/app/tls-config.properties";
    private static final String KEYS_CONF_PATH = "/app/crypto-config.properties";

    // Cryptographic constants
    private static final int KEYSIZE = 256;
    private static final String ALGORITHM = "AES";
    private static SSLContext sslContext;

    private static final Properties tlsConfig = new Properties();
    private static final Properties cryptoConfig = new Properties();

    private static FsManager fsManager;

    // Custom logger with a custom formatter
    private static final Logger logger = Logger.getLogger(StorageService.class.getName());

    static {
        initLogger();
        getConfigs();
        initializeSSLContext();
    }

    public static void main(String[] args) {
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

    private static void getConfigs() {
        try (FileInputStream tls = new FileInputStream(TLS_CONF_PATH);
                FileInputStream keys = new FileInputStream(KEYS_CONF_PATH)) {
            tlsConfig.load(tls);
            cryptoConfig.load(keys);
            logger.info("Configurations loaded successfully from " + TLS_CONF_PATH + " and " + KEYS_CONF_PATH);
        } catch (IOException ex) {
            logger.log(Level.WARNING, "Error loading configuration: " + ex.getMessage(), ex);
        }
    }

    private static void initLogger() {
        try {
            Logger rootLogger = Logger.getLogger("");
            Handler[] handlers = rootLogger.getHandlers();
            if (handlers.length > 0 && handlers[0] instanceof ConsoleHandler) {
                rootLogger.removeHandler(handlers[0]);
            }
            ConsoleHandler handler = new ConsoleHandler();
            handler.setFormatter(new SimpleFormatter() {
                private static final String format = "[%1$tT,%1$tL] [%2$-7s] [%3$s]: %4$s %n";

                @Override
                public synchronized String format(LogRecord lr) {
                    return String.format(format,
                            new Date(lr.getMillis()),
                            lr.getLevel().getLocalizedName(),
                            lr.getLoggerName(),
                            lr.getMessage());
                }
            });
            logger.addHandler(handler);
            logger.info("Logger initialized with custom console formatter.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void initializeSSLContext() {
        try {
            logger.info("Initializing SSL context.");
            logger.info("Loading keystore from: " + KEYSTORE_PATH);
            KeyStore ks = loadKeyStore();
            logger.info("Keystore loaded with " + ks.size() + " entries.");

            logger.info("Loading truststore from: " + TRUSTSTORE_PATH);
            KeyStore ts = loadTrustStore();
            logger.info("Truststore loaded with " + ts.size() + " entries.");

            // Initialize KeyManagerFactory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, getKeystorePassword());

            // Initialize TrustManagerFactory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            // Initialize SSLContext
            sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

            logger.info("SSL context successfully initialized.");
        } catch (IOException | GeneralSecurityException e) {
            logger.log(Level.SEVERE, "SSL Context Initialization Failed", e);
            throw new RuntimeException(e);
        }
    }

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

    private static SSLServerSocket createServerSocket() throws IOException {
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

    private static void acceptConnections(SSLServerSocket serverSocket) {
        ExecutorService executor = Executors.newCachedThreadPool();
        logger.info("Ready to accept client connections.");
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                logger.info("Accepted connection from " + clientSocket.getRemoteSocketAddress());
                // Wrap the accepted socket in our custom SocketStreams class.
                SocketStreams streams = new SocketStreams(clientSocket);
                executor.submit(() -> handleClientConnection(streams));
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error accepting client connection", e);
            }
        }
        executor.shutdown();
    }

    private static void handleClientConnection(SocketStreams streams) {
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

    private static void processStorageRequest(Wrapper request, ObjectOutputStream oos)
            throws CryptoException, InvalidAlgorithmParameterException {
        logger.info("=== Starting processStorageRequest ===");
        try {
            logger.info("Received wrapper: " + request);
            // Deserialize the incoming request message as a RequestServiceMessage.
            logger.info("Deserializing RequestServiceMessage...");
            RequestServiceMessage requestServiceMessage = (RequestServiceMessage) RandomUtils
                    .deserialize(request.getMessage());
            logger.info("RequestServiceMessage deserialized successfully.");

            byte messageType = request.getMessageType();
            UUID messageId = request.getMessageId();
            logger.info("MessageType: " + messageType + " | MessageId: " + messageId);

            // Convert and retrieve the shared key used for decrypting the SGT.
            SecretKey key = CryptoStuff.getInstance()
                    .convertStringToSecretKey(cryptoConfig.getProperty("STORAGE_TGS_KEY"));
            logger.info("Converted shared key from configuration.");

            // Decrypt the Service Granting Ticket (SGT)
            byte[] encryptedSgt = requestServiceMessage.getEncryptedSGT();
            logger.info("Encrypted SGT received (length: " + encryptedSgt.length + "). Attempting decryption...");
            byte[] sgtBytes = CryptoStuff.getInstance().decrypt(key, encryptedSgt);
            ServiceGrantingTicket sgt = (ServiceGrantingTicket) RandomUtils.deserialize(sgtBytes);
            logger.info("ServiceGrantingTicket decrypted successfully. [ClientId: " + sgt.getClientId()
                    + ", ClientAddress: " + sgt.getClientAddress() + "]");

            // Decrypting the Authenticator
            byte[] encryptedAuth = requestServiceMessage.getAuthenticator();
            logger.info("Encrypted Authenticator received (length: " + encryptedAuth.length
                    + "). Attempting decryption...");
            byte[] authBytes = CryptoStuff.getInstance().decrypt(sgt.getKey(), encryptedAuth);
            Authenticator authenticator = (Authenticator) RandomUtils.deserialize(authBytes);
            logger.info("Authenticator decrypted successfully. Timestamp: " + authenticator.getTimestamp());

            // Validate Authenticator
            logger.info("Validating Authenticator for client " + sgt.getClientId() + " at address "
                    + sgt.getClientAddress());
            if (!authenticator.isValid(sgt.getClientId(), sgt.getClientAddress())) {
                logger.warning("Authenticator validation failed. Aborting request processing.");
                return;
            }
            logger.info("Authenticator is valid.");

            // Extract command and execute accordingly
            Command command = sgt.getCommand();
            String userId = sgt.getClientId();
            String path = userId +  command.getPath();
            logger.info(
                    "Command received from client [" + userId + "]: " + command.getCommand() + " for path: " + path);

            FilePayload content = command.getPayload();
            List<String> files = null;
            switch (command.getCommand()) {
                case GET:
                    logger.info("Executing GET command...");
                    String fileContent = fsManager.readFile(path);
                    logger.info("GET command executed. File read from path: " + path);
                    // Optionally: attach fileContent in the response if needed.
                    break;
                case PUT:
                    logger.info("Executing PUT command...");
                    if (content == null) {
                        logger.warning("PUT command missing content for path: " + path);
                    } else {
                        fsManager.writeFile(path, content);
                        logger.info("PUT command executed. File written at: " + path);
                    }
                    break;
                case RM:
                    logger.info("Executing RM command...");
                    fsManager.deleteFile(path);
                    logger.info("RM command executed. File deleted at: " + path);
                    break;
                case LS:
                    logger.info("Executing LS command...");
                    files = fsManager.listFolder(path);
                    logger.info("LS command executed. Listed files in folder: " + path);
                    break;
                default:
                    logger.warning("Unknown command received: " + command.getCommand());
            }

            // Prepare and send the response message
            byte[] responseContent = (files != null) ? String.join("\n", files).getBytes(StandardCharsets.UTF_8)
                    : new byte[0];
            ResponseServiceMessage res = new ResponseServiceMessage(new CommandReturn(command, responseContent), null);
            logger.info("Sending response back to client...");
            oos.writeObject(res);
            oos.flush();
            logger.info("Response sent successfully.");
        } catch (IOException | ClassNotFoundException ex) {
            logger.log(Level.WARNING, "Error processing storage request: " + ex.getMessage(), ex);
        }
        logger.info("=== Finished processStorageRequest ===");
    }

    // ----------------------- Configuration Getters -----------------------

    private static String[] getTlsProtocols() {
        String protocols = tlsConfig.getProperty("TLS-PROT-ENF", "TLSv1.2");
        return protocols.split(",");
    }

    private static String[] getCipherSuites() {
        String ciphers = tlsConfig.getProperty("CIPHERSUITES", "");
        return ciphers.isEmpty() ? new String[0] : ciphers.split(",");
    }

    private static boolean needsClientAuth() {
        return "MUTUAL".equalsIgnoreCase(System.getProperty("TLS-AUTH", "NONE"));
    }

    private static char[] getKeystorePassword() {
        return "py6IDOytDVeqGjG6eflXoQ==".toCharArray();
    }

    private static char[] getTruststorePassword() {
        return "BNCc7MdZuBJJYJQuRVnjbA==".toCharArray();
    }

    // ----------------------- Inner Classes -----------------------

    private static class SocketStreams implements AutoCloseable {
        private SSLSocket socket;
        private ObjectOutputStream oos;
        private ObjectInputStream ois;

        public SocketStreams(SSLSocket socket) throws IOException {
            this.socket = socket;
            // Perform SSL handshake immediately.
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
}
