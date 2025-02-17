package dmsrosa.kerberosfs;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.crypto.CryptoException;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.RequestAuthenticationMessage;
import dmsrosa.kerberosfs.messages.ResponseAuthenticationMessage;
import dmsrosa.kerberosfs.messages.TicketGrantingTicket;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class AuthenticationService {

    private static final Logger logger = Logger.getLogger(AuthenticationService.class.getName());

    // Configuration constants
    private static final String KEYSTORE_PATH = "/app/keystore.jks";
    private static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private static final String CRYPTO_CONFIG_PATH = "/app/crypto-config.properties";
    private static final String TLS_CONFIG_PATH = "/app/tls-config.properties";
    private static final int SERVICE_PORT = 8081;
    private static final String TGS_KEY_ID = "TGS_AS_KEY";

    // Cryptographic constants
    private static final String DH_ALGORITHM = "DH";
    private static final String SYM_ALGORITHM = "AES";
    private static final int DH_KEY_SIZE = 2048;

    private static SecretKey tgsKey;
    private static final Map<UUID, SecretKey> clientSessions;
    private static SSLContext sslContext;

    private static final Properties tlsConfig;
    private static final Properties cryptoConfig;

    private static final Authentication authentication;

    static {
        configureLogger();
        try {
            initializeSSLContext();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to initialize SSL context", e);
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        cryptoConfig = loadCryptoConfig();
        tlsConfig = loadTLSConfig();
        clientSessions = new ConcurrentHashMap<>();
        authentication = new Authentication();
    }

    public static void main(String[] args) {
        try (SSLServerSocket serverSocket = createServerSocket()) {
            logger.info("Authentication service started on port " + SERVICE_PORT);
            acceptConnections(serverSocket);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start authentication service", e);
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ----------------------- Initialization Methods -----------------------

    private static void configureLogger() {
        Logger rootLogger = Logger.getLogger("");
        Arrays.stream(rootLogger.getHandlers()).forEach(rootLogger::removeHandler);

        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new LogFormatter());
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        logger.setLevel(Level.FINEST);
    }

    private static Properties loadTLSConfig() {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream(TLS_CONFIG_PATH)) {
            props.load(input);
            logger.info("TLS configuration loaded successfully from: " + TLS_CONFIG_PATH);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to load TLS configuration from: " + TLS_CONFIG_PATH, e);
            throw new RuntimeException("Failed to load TLS configuration", e);
        }
        return props;
    }

    private static Properties loadCryptoConfig() {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream(CRYPTO_CONFIG_PATH)) {
            props.load(input);
            String tgsKeyStr = props.getProperty(TGS_KEY_ID, "");
            tgsKey = CryptoStuff.getInstance().convertStringToSecretKey(tgsKeyStr);
            logger.info("Crypto configuration loaded successfully from: " + CRYPTO_CONFIG_PATH);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to load crypto configuration from: " + CRYPTO_CONFIG_PATH, e);
            throw new RuntimeException("Failed to load crypto configuration", e);
        }
        return props;
    }

    private static void initializeSSLContext() throws Exception {
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

        sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        logger.info("SSL context successfully initialized.");
    }

    private static SSLServerSocket createServerSocket() throws IOException {
        SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(SERVICE_PORT);
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

    private static void acceptConnections(SSLServerSocket serverSocket) {
        logger.info("Ready to accept client connections.");
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                logger.info("Accepted connection from " + clientSocket.getRemoteSocketAddress());
                // Handle client connection on a new thread.
                new Thread(() -> {
                    try {
                        handleClientConnection(new SocketStreams(clientSocket));
                    } catch (IOException e) {
                        logger.log(Level.SEVERE, "Error handling client connection", e);
                    }
                }).start();
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error accepting client connection", e);
            }
        }
    }

    // ----------------------- Client Request Handling -----------------------

    private static void handleClientConnection(SocketStreams streams) {
        logger.info("Client connected: " + streams.getRemoteAddress());
        try {
            while (true) {
                try {
                    Wrapper request = (Wrapper) streams.getOIS().readObject();
                    if (request == null) {
                        logger.info("Client closed the connection.");
                        break;
                    }
                    logger.info("Received request: " + request);
                    processRequest(request, streams.getOOS());
                } catch (EOFException e) {
                    logger.info("Client disconnected normally.");
                    break;
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error processing client request", e);
                    e.printStackTrace();
                    break;
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error with client " + streams.getRemoteAddress(), e);
        } finally {
            streams.close();
            logger.info("Closed connection with " + streams.getRemoteAddress());
        }
    }

    private static void processRequest(Wrapper request, ObjectOutputStream oos) throws Exception {
        logger.info("Processing authentication request: " + request);
        switch (request.getMessageType()) {
            case 0:
                handleKeyExchange(request, oos);
                break;
            case 1:
                handleAuthentication(request, oos);
                break;
            default:
                sendErrorResponse(oos, request.getMessageId(), 400, "Invalid message type");
        }
    }

    private static void handleKeyExchange(Wrapper request, ObjectOutputStream oos) throws Exception {
        logger.info("Starting Diffie-Hellman key exchange for request " + request.getMessageId());
        KeyPair keyPair = generateDHKeyPair();
        PublicKey clientKey = parsePublicKey(request.getMessage());
        logger.fine("Client public key parsed successfully.");

        SecretKey sharedKey = generateSharedKey(keyPair, clientKey);
        clientSessions.put(request.getMessageId(), sharedKey);

        sendResponse(oos, request.getMessageType(), keyPair.getPublic().getEncoded(), request.getMessageId());
        logger.info("Key exchange successful; shared key stored for request " + request.getMessageId());
    }

    private static void handleAuthentication(Wrapper request, ObjectOutputStream oos) throws Exception {
        logger.info("Handling authentication for request " + request.getMessageId());
        SecretKey clientKey = clientSessions.get(request.getMessageId());
        if (clientKey == null) {
            logger.warning("No session key found for request " + request.getMessageId());
            sendErrorResponse(oos, request.getMessageId(), 401, "No valid session key");
            return;
        }

        RequestAuthenticationMessage authRequest = decryptRequest(clientKey, request);
        logger.info("Decrypted authentication request for client: " + authRequest.getClientId());
        validateAuthentication(authRequest, oos, request.getMessageId());
    }

    private static RequestAuthenticationMessage decryptRequest(SecretKey key, Wrapper request)
            throws CryptoException, InvalidAlgorithmParameterException, IOException, ClassNotFoundException {
        logger.fine("Decrypting authentication request using shared key.");
        byte[] decrypted = CryptoStuff.getInstance().decrypt(key, request.getMessage());
        Object obj = RandomUtils.deserialize(decrypted);
        if (!(obj instanceof RequestAuthenticationMessage)) {
            throw new CryptoException("Decrypted object is not a RequestAuthenticationMessage");
        }
        return (RequestAuthenticationMessage) obj;
    }

    private static void validateAuthentication(RequestAuthenticationMessage authRequest,
                                                 ObjectOutputStream oos, UUID requestId) throws Exception {
        logger.info("Validating authentication for client: " + authRequest.getClientId());
        byte[] userKey = authentication.getUsernamePassword(authRequest.getClientId());
        if (userKey == null) {
            logger.warning("Invalid credentials for client " + authRequest.getClientId());
            sendErrorResponse(oos, requestId, 401, "Invalid credentials");
            return;
        }
        SecretKey userSecret = CryptoStuff.getInstance().convertByteArrayToSecretKey(userKey);
        ResponseAuthenticationMessage response = createAuthenticationResponse(authRequest);
        sendEncryptedResponse(oos, requestId, response, userSecret);
    }

    private static ResponseAuthenticationMessage createAuthenticationResponse(RequestAuthenticationMessage request)
            throws Exception {
        logger.info("Creating authentication response for client " + request.getClientId());
        SecretKey sessionKey = KeyGenerator.getInstance(SYM_ALGORITHM).generateKey();
        TicketGrantingTicket tgt = new TicketGrantingTicket(
                request.getClientId(),
                request.getClientAddress(),
                request.getServiceId(),
                sessionKey
        );
        byte[] encryptedTgt = CryptoStuff.getInstance().encrypt(tgsKey, RandomUtils.serialize(tgt));
        return new ResponseAuthenticationMessage(sessionKey, encryptedTgt);
    }

    private static void sendEncryptedResponse(ObjectOutputStream oos, UUID requestId,
                                              ResponseAuthenticationMessage response, SecretKey key) throws Exception {
        logger.info("Sending encrypted authentication response for request " + requestId);
        byte[] responseBytes = RandomUtils.serialize(response);
        byte[] encryptedResponse = CryptoStuff.getInstance().encrypt(key, responseBytes);
        sendResponse(oos, (byte) 1, encryptedResponse, requestId);
    }

    private static void sendResponse(ObjectOutputStream oos, byte type, byte[] data, UUID requestId)
            throws IOException {
        logger.fine("Sending response for request " + requestId);
        Wrapper wrapper = new Wrapper(type, data, requestId, 200);
        oos.writeObject(wrapper);
        oos.flush();
        logger.fine("Response sent successfully for request " + requestId);
    }

    private static void sendErrorResponse(ObjectOutputStream oos, UUID requestId, int code, String message) {
        try {
            logger.info("Sending error response for request " + requestId + ": " + message);
            Wrapper wrapper = new Wrapper((byte) -1, message.getBytes(), requestId, code);
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to send error response for request " + requestId, e);
            e.printStackTrace();
        }
    }

    // ----------------------- Helper Methods -----------------------

    private static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        logger.fine("Generating Diffie-Hellman key pair with key size " + DH_KEY_SIZE);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyGen.initialize(DH_KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();
        logger.fine("Diffie-Hellman key pair generated successfully.");
        return keyPair;
    }

    private static PublicKey parsePublicKey(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        logger.fine("Parsing client public key from received bytes.");
        return KeyFactory.getInstance(DH_ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private static SecretKey generateSharedKey(KeyPair keyPair, PublicKey clientKey)
            throws InvalidKeyException, NoSuchAlgorithmException {
        logger.fine("Generating shared secret using Diffie-Hellman.");
        KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(clientKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] derivedKey = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
        SecretKey sharedKey = new SecretKeySpec(derivedKey, SYM_ALGORITHM);
        logger.fine("Shared secret derived successfully.");
        return sharedKey;
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

    private static String[] getTlsProtocols() {
        String protocols = tlsConfig.getProperty("TLS-PROT-ENF", "TLSv1.2");
        return protocols.split(",");
    }

    private static String[] getCipherSuites() {
        String ciphers = tlsConfig.getProperty("CIPHERSUITES", "");
        return ciphers.isEmpty() ? new String[0] : ciphers.split(",");
    }

    private static boolean needsClientAuth() {
        return "MUTUAL".equalsIgnoreCase(tlsConfig.getProperty("TLS-AUTH", "NONE"));
    }

    private static char[] getKeystorePassword() {
        return "UXwE2u1raTW3rlPcSEbmFA==".toCharArray();
    }

    private static char[] getTruststorePassword() {
        return "E4kLV4p5AGvc2w+EtUoWfA==".toCharArray();
    }

    // ----------------------- Inner Classes -----------------------

    private static class LogFormatter extends SimpleFormatter {
        private static final String FORMAT = "[%1$tT,%1$tL] [%2$-7s] [%3$s]: %4$s %n";
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
     * SocketStreams encapsulates the ObjectInputStream and ObjectOutputStream for an SSLSocket.
     * It starts the SSL handshake immediately upon creation.
     */
    private static class SocketStreams implements AutoCloseable {
        private SSLSocket socket;
        private ObjectOutputStream oos;
        private ObjectInputStream ois;

        public SocketStreams(SSLSocket socket) throws IOException {
            this.socket = socket;
            // Initiate SSL handshake before creating streams.
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
            try {
                if (oos != null) oos.close();
            } catch (Exception ignored) { }
            try {
                if (ois != null) ois.close();
            } catch (Exception ignored) { }
            try {
                if (socket != null && !socket.isClosed()) socket.close();
            } catch (Exception ignored) { }
        }
    }
}
