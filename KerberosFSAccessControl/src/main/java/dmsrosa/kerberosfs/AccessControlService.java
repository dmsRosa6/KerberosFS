package dmsrosa.kerberosfs;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Deque;
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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.commands.Command;
import dmsrosa.kerberosfs.crypto.CryptoException;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.MessageStatus;
import dmsrosa.kerberosfs.messages.RequestTGSMessage;
import dmsrosa.kerberosfs.messages.ResponseTGSMessage;
import dmsrosa.kerberosfs.messages.ServiceGrantingTicket;
import dmsrosa.kerberosfs.messages.TicketGrantingTicket;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.Pair;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class AccessControlService {

    // Configuration constants (unchanged)
    private final String KEYSTORE_PATH = "/app/keystore.jks";
    private final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private final String TLS_VERSION = "TLSv1.2";
    private final int PORT = 8082;
    private final String TLS_CONF_PATH = "/app/tls-config.properties";
    private final String KEYS_CONF_PATH = "/app/keys.properties";

    // Cryptographic constants
    private final int KEYSIZE = 256;
    private final String ALGORITHM = "AES";

    // Instance fields for keys, services, and configuration
    private SecretKey tgsKey;
    private SecretKey storageKey;
    private AccessControl accessControl;
    private SSLContext sslContext;

    private final Properties tlsConfig = new Properties();
    private final Properties keysConfig = new Properties();

    // Logger (set to essential logging)
    private final Logger logger = Logger.getLogger(AccessControlService.class.getName());

    // Constructor initializes configurations and SSL
    public AccessControlService() {
        initLogger();
        getConfigs();
        initializeSSLContext();
        configureLogger();
    }

    public void run() {
        // Set logger level as needed (INFO here for production)
        logger.setLevel(Level.INFO);

        // Convert string properties to secret keys
        tgsKey = CryptoStuff.getInstance().convertStringToSecretKey(keysConfig.getProperty("TGS_KEY"));
        storageKey = CryptoStuff.getInstance().convertStringToSecretKey(keysConfig.getProperty("STORAGE_KEY"));
        accessControl = new AccessControl();
        logger.info("Access control service started on port " + PORT);

        try (SSLServerSocket serverSocket = createServerSocket()) {
            acceptConnections(serverSocket);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start access control service: " + e.getMessage(), e);
            System.exit(1);
        }
    }

    // ----------------------- Configuration & Initialization -----------------------

    private void configureLogger() {
        Logger rootLogger = Logger.getLogger("");
        Arrays.stream(rootLogger.getHandlers()).forEach(rootLogger::removeHandler);

        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new LogFormatter());
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        logger.setLevel(Level.INFO);
    }

    private void getConfigs() {
        try (FileInputStream tlsStream = new FileInputStream(TLS_CONF_PATH);
             FileInputStream keysStream = new FileInputStream(KEYS_CONF_PATH)) {
            tlsConfig.load(tlsStream);
            keysConfig.load(keysStream);
            logger.info("Configurations loaded from " + TLS_CONF_PATH + " and " + KEYS_CONF_PATH);
        } catch (IOException ex) {
            logger.warning("Error loading configuration: " + ex.getMessage());
        }
    }

    private void initLogger() {
        try {
            Logger rootLogger = Logger.getLogger("");
            Handler[] handlers = rootLogger.getHandlers();
            if (handlers.length > 0 && handlers[0] instanceof ConsoleHandler) {
                rootLogger.removeHandler(handlers[0]);
            }
            ConsoleHandler handler = new ConsoleHandler();
            handler.setFormatter(new SimpleFormatter() {
                private final String format = "[%1$tT,%1$tL] [%2$-7s] [%3$s]: %4$s %n";
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initializeSSLContext() {
        try {
            logger.info("Initializing SSL context.");
            logger.info("Loading keystore from: " + KEYSTORE_PATH);
            KeyStore ks = loadKeyStore();
            logger.info("Keystore loaded with " + ks.size() + " entries.");

            logger.info("Loading truststore from: " + TRUSTSTORE_PATH);
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
            logger.log(Level.SEVERE, "SSL Context Initialization Failed: " + e.getMessage(), e);
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
                logger.log(Level.WARNING, "Error accepting client connection: " + e.getMessage(), e);
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
                    processAccessControlRequest(request, streams.getOOS());
                } catch (EOFException e) {
                    logger.info("Client disconnected normally.");
                    break;
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error processing client request: " + e.getMessage(), e);
                    break;
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error handling client " + streams.getRemoteAddress() + ": " + e.getMessage(), e);
        }
    }

    // ----------------------- Request Processing -----------------------

    private void processAccessControlRequest(Wrapper request, ObjectOutputStream oos) throws CryptoException {
        try {
            logger.info("Processing access control request, messageId: " + request.getMessageId());
            
            // Deserialize the incoming RequestTGSMessage
            RequestTGSMessage requestTGSMessage = (RequestTGSMessage) RandomUtils.deserialize(request.getMessage());
            String serviceId = requestTGSMessage.getServiceId();
            byte[] tgtSerialized = requestTGSMessage.getEncryptedTGT();
            byte[] authenticatorSerialized = requestTGSMessage.getEncryptedAuthenticator();

            // Decrypt and deserialize TGT using tgsKey
            tgtSerialized = CryptoStuff.getInstance().decrypt(tgsKey, tgtSerialized);
            TicketGrantingTicket tgt = (TicketGrantingTicket) RandomUtils.deserialize(tgtSerialized);
            SecretKey keyClientTGS = tgt.getKey();

            // Decrypt and deserialize authenticator using the key from TGT
            authenticatorSerialized = CryptoStuff.getInstance().decrypt(keyClientTGS, authenticatorSerialized);
            Authenticator authenticator = (Authenticator) RandomUtils.deserialize(authenticatorSerialized);

            logger.info("Validating authenticator...");
            if (!authenticator.isValid(tgt.getClientId(), tgt.getClientAddress())) {
                logger.warning("Authenticator validation failed for client: " + tgt.getClientId());
                Wrapper errorWrapper = new Wrapper((byte) 4, null, request.getMessageId(), 
                        MessageStatus.UNAUTHORIZED.getCode());
                oos.writeObject(errorWrapper);
                return;
            }

            logger.info("Validating command path...");
            Command command = authenticator.getCommand();
            if (!accessControl.hasPermission(authenticator.getClientId(), command.getCommand())) {
                logger.warning("Access denied for client " + authenticator.getClientId() 
                        + " for command: " + command.getCommand());
                Wrapper errorWrapper = new Wrapper((byte) 4, null, request.getMessageId(),
                        MessageStatus.UNAUTHORIZED.getCode());
                oos.writeObject(errorWrapper);
                return;
            }
            
            Pair<Boolean, String> validPath = validateAndNormalizePath(command.getPath());
            if (!validPath.first) {
                logger.warning("Invalid command path received from client " + authenticator.getClientId());
                Wrapper errorWrapper = new Wrapper((byte) 4, null, request.getMessageId(),
                        MessageStatus.FORBIDDEN.getCode());
                oos.writeObject(errorWrapper);
                return;
            }
            command.setPath(validPath.second);

            // Generate a key for the service ticket
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEYSIZE);
            SecretKey generatedKey = kg.generateKey();

            // Create the Service Granting Ticket (SGT)
            ServiceGrantingTicket sgt = new ServiceGrantingTicket(
                    tgt.getClientId(), tgt.getClientAddress(), serviceId, generatedKey, command);
            LocalDateTime issueTime = sgt.getIssueTime();

            // Serialize and encrypt the SGT with storageKey
            byte[] sgtSerialized = RandomUtils.serialize(sgt);
            sgtSerialized = CryptoStuff.getInstance().encrypt(storageKey, sgtSerialized);

            // Create the response message and encrypt it with the key from TGT
            ResponseTGSMessage responseMsg = new ResponseTGSMessage(generatedKey, serviceId, issueTime, sgtSerialized);
            byte[] msgSerialized = RandomUtils.serialize(responseMsg);
            msgSerialized = CryptoStuff.getInstance().encrypt(keyClientTGS, msgSerialized);

            // Wrap and send the response
            Wrapper wrapperMessage = new Wrapper((byte) 4, msgSerialized, request.getMessageId(),
                    MessageStatus.OK_NO_CONTENT.getCode());
            oos.writeObject(wrapperMessage);
            logger.info("Access control request processed successfully for client: " + tgt.getClientId());
                        
        } catch (IOException | NoSuchAlgorithmException | ClassNotFoundException 
                | InvalidAlgorithmParameterException | CryptoException e) {
            logger.log(Level.WARNING, "Error processing access control request: " + e.getMessage(), e);
        }
    }

    // ----------------------- Helper Methods -----------------------

    private Pair<Boolean, String> validateAndNormalizePath(String path) {
        boolean isAbsolute = path.startsWith("/");
        Deque<String> stack = new ArrayDeque<>();
        String[] tokens = path.split("/");
        for (String token : tokens) {
            if (token.isEmpty() || token.equals(".")) {
                continue;
            }
            if (token.equals("..")) {
                if (stack.isEmpty()) {
                    return new Pair<>(false, null);
                }
                stack.pop();
            } else {
                stack.push(token);
            }
        }
        List<String> normalizedTokens = new ArrayList<>(stack);
        Collections.reverse(normalizedTokens);
        String normalizedPath = (isAbsolute ? "/" : "") + String.join("/", normalizedTokens);
        if (normalizedPath.isEmpty() && isAbsolute) {
            normalizedPath = "/";
        }
        return new Pair<>(true, normalizedPath);
    }

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
        return "ORsksvIlvOj2JeLdAdaUMQ==".toCharArray();
    }

    private char[] getTruststorePassword() {
        return "sZOOqRMTJXh1+yjQhI9qdQ==".toCharArray();
    }

    // ----------------------- Inner Classes -----------------------

    private class LogFormatter extends SimpleFormatter {
        private final String FORMAT = "[%1$tT,%1$tL] [%2$-7s] [%3$s]: %4$s %n";
        @Override
        public String format(LogRecord record) {
            return String.format(FORMAT,
                    new Date(record.getMillis()),
                    record.getLevel().getLocalizedName(),
                    record.getLoggerName(),
                    record.getMessage());
        }
    }

    /**
     * SocketStreams encapsulates ObjectInputStream and ObjectOutputStream for an SSLSocket.
     * It performs the SSL handshake immediately upon creation.
     */
    private class SocketStreams implements AutoCloseable {
        private final SSLSocket socket;
        private ObjectOutputStream oos;
        private ObjectInputStream ois;

        public SocketStreams(SSLSocket socket) throws IOException {
            this.socket = socket;
            socket.startHandshake();
        }

        public ObjectOutputStream getOOS() throws IOException {
            if (oos == null) {
                oos = new ObjectOutputStream(socket.getOutputStream());
                oos.flush();
            }
            return oos;
        }

        public ObjectInputStream getOIS() throws IOException {
            if (ois == null) {
                ois = new ObjectInputStream(socket.getInputStream());
            }
            return ois;
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
    
    // Main method to bootstrap the service
    public static void main(String[] args) {
        AccessControlService service = new AccessControlService();
        service.run();
    }
}
