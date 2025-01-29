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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

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
    private static final String TLS_VERSION = "TLSv1.2";
    private static final String KEYSTORE_PATH = "/app/keystore.jks";
    private static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private static final String CRYPTO_CONFIG_PATH = "/app/crypto-config.properties";
    private static final int SERVICE_PORT = 8081;
    private static final long REQUEST_TIMEOUT = 10000;
    private static final String TGS_KEY_ID = "TGS_AS_KEY";
    
    // Cryptographic constants
    private static final String DH_ALGORITHM = "DH";
    private static final String SYM_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;
    private static final int DH_KEY_SIZE = 2048;
    
    private static SecretKey tgsKey;
    private static final Map<String, SecretKey> clientKeys = new ConcurrentHashMap<>();
    private static SSLContext sslContext;

    static {
        configureLogger();
        loadCryptoConfig();
        initializeSSLContext();
    }

    public static void main(String[] args) {
        try (SSLServerSocket serverSocket = createServerSocket()) {
            logger.info("Authentication service started on port " + SERVICE_PORT);
            acceptConnections(serverSocket);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start authentication service", e);
            System.exit(1);
        }
    }

    // Initialization methods
    private static void configureLogger() {
        Logger rootLogger = Logger.getLogger("");
        Arrays.stream(rootLogger.getHandlers()).forEach(rootLogger::removeHandler);
        
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new LogFormatter());
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        logger.setLevel(Level.INFO);
    }

    private static void loadCryptoConfig() {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream(CRYPTO_CONFIG_PATH)) {
            props.load(input);
            tgsKey = CryptoStuff.getInstance().convertStringToSecretKey(
                props.getProperty(TGS_KEY_ID, ""));
            logger.info("Loaded TGS key successfully");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load crypto config", e);
        }
    }

    private static void initializeSSLContext() {
        try {
            logger.info("Loading keystore from: " + KEYSTORE_PATH);
            KeyStore ks = loadKeyStore();
            logger.info("Keystore contains " + ks.size() + " entries");
    
            logger.info("Loading truststore from: " + TRUSTSTORE_PATH);
            KeyStore ts = loadTrustStore();
            logger.info("Truststore contains " + ts.size() + " entries");
    
            // Rest of initialization
        } catch (IOException | GeneralSecurityException e) {
            logger.log(Level.SEVERE, "SSL Context Initialization Failed", e);
            throw new RuntimeException(e);
        }
    }

    // Server operations
    private static SSLServerSocket createServerSocket() throws IOException {
        SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory()
            .createServerSocket(SERVICE_PORT);
        
        serverSocket.setEnabledProtocols(getTlsProtocols());
        serverSocket.setEnabledCipherSuites(getCipherSuites());
        serverSocket.setNeedClientAuth(needsClientAuth());
        
        return serverSocket;
    }

    private static void acceptConnections(SSLServerSocket serverSocket) {
        ExecutorService executor = Executors.newCachedThreadPool();
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                executor.submit(() -> handleClientConnection(clientSocket));
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error accepting client connection", e);
            }
        }
        executor.shutdown();
    }

    private static void handleClientConnection(SSLSocket clientSocket) {
        try (clientSocket;
             ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());
             ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream())) {
            
            clientSocket.startHandshake();
            logger.info("Client connected: " + clientSocket.getRemoteSocketAddress());

            while (!clientSocket.isClosed()) {
                Wrapper request = (Wrapper) ois.readObject();
                processRequest(request, oos);
            }
        } catch (EOFException e) {
            logger.info("Client disconnected normally");
        } catch (ClassNotFoundException | IOException e) {
            logger.log(Level.WARNING, "Client connection error", e);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error handling client", e);
        }
    }

    private static void processRequest(Wrapper request, ObjectOutputStream oos) {
        try {
            switch (request.getMessageType()) {
                case 0 -> handleKeyExchange(request, oos);
                case 1 -> handleAuthentication(request, oos);
                default -> sendErrorResponse(oos, request.getMessageId(), 400, "Invalid message type");
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to send response", e);
        }
    }

    // Request handlers
    private static void handleKeyExchange(Wrapper request, ObjectOutputStream oos) throws IOException {
        try {
            KeyPair keyPair = generateDHKeyPair();
            PublicKey clientKey = parsePublicKey(request.getMessage());
            
            SecretKey sharedKey = generateSharedKey(keyPair, clientKey);
            clientKeys.put(request.getMessageId().toString(), sharedKey);
            
            sendResponse(oos, request.getMessageType(), 
                keyPair.getPublic().getEncoded(), request.getMessageId());
            
        } catch (GeneralSecurityException e) {
            logger.log(Level.WARNING, "Key exchange failed", e);
            sendErrorResponse(oos, request.getMessageId(), 500, "Key exchange error");
        }
    }

    private static void handleAuthentication(Wrapper request, ObjectOutputStream oos) throws IOException {
        try {
            SecretKey clientKey = clientKeys.get(request.getMessageId().toString());
            if (clientKey == null) {
                sendErrorResponse(oos, request.getMessageId(), 401, "No valid session key");
                return;
            }

            RequestAuthenticationMessage authRequest = decryptRequest(clientKey, request);
            validateAuthentication(authRequest, oos, request.getMessageId());
            
        } catch (CryptoException | InvalidAlgorithmParameterException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Authentication failed", e);
            sendErrorResponse(oos, request.getMessageId(), 401, "Authentication error");
        } catch (NoSuchAlgorithmException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
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

    private static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyGen.initialize(DH_KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    private static PublicKey parsePublicKey(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance(DH_ALGORITHM)
            .generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private static SecretKey generateSharedKey(KeyPair keyPair, PublicKey clientKey) 
        throws InvalidKeyException, NoSuchAlgorithmException {
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(clientKey, true);
        
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] derivedKey = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
        return new SecretKeySpec(derivedKey, SYM_ALGORITHM);
    }

    private static RequestAuthenticationMessage decryptRequest(SecretKey key, Wrapper request)
        throws CryptoException, InvalidAlgorithmParameterException, IOException, ClassNotFoundException {
        
        byte[] decrypted = CryptoStuff.getInstance().decrypt(key, request.getMessage());
        return (RequestAuthenticationMessage) RandomUtils.deserialize(decrypted);
    }

    private static void validateAuthentication(RequestAuthenticationMessage authRequest, 
            ObjectOutputStream oos, UUID requestId) throws IOException, NoSuchAlgorithmException {
        
        byte[] userKey = Authentication.getUsernamePassword(authRequest.getClientId());
        if (userKey == null) {
            sendErrorResponse(oos, requestId, 401, "Invalid credentials");
            return;
        }

        SecretKey userSecret = CryptoStuff.getInstance().convertByteArrayToSecretKey(userKey);
        ResponseAuthenticationMessage response = createAuthenticationResponse(authRequest);
        sendEncryptedResponse(oos, requestId, response, userSecret);
    }

    private static ResponseAuthenticationMessage createAuthenticationResponse(RequestAuthenticationMessage request) 
        throws NoSuchAlgorithmException, IOException {
        
        SecretKey sessionKey = KeyGenerator.getInstance(SYM_ALGORITHM)
            .generateKey();
        
        TicketGrantingTicket tgt = new TicketGrantingTicket(
            request.getClientId(),
            request.getClientAddress(),
            request.getServiceId(),
            sessionKey
        );
        
        byte[] encryptedTgt = null;
        try {
            encryptedTgt = CryptoStuff.getInstance().encrypt(tgsKey, RandomUtils.serialize(tgt));
        } catch (CryptoException | InvalidAlgorithmParameterException ex) {
        }
        return new ResponseAuthenticationMessage(sessionKey, encryptedTgt);
    }

    // Response handling
    private static void sendEncryptedResponse(ObjectOutputStream oos, UUID requestId, 
            ResponseAuthenticationMessage response, SecretKey key) throws IOException {
        
        try {
            byte[] responseBytes = RandomUtils.serialize(response);
            byte[] encryptedResponse = CryptoStuff.getInstance().encrypt(key, responseBytes);
            sendResponse(oos, (byte) 1, encryptedResponse, requestId);
        } catch (CryptoException | InvalidAlgorithmParameterException e) {
            sendErrorResponse(oos, requestId, 500, "Response encryption failed");
        }
    }

    private static void sendResponse(ObjectOutputStream oos, byte type, byte[] data, UUID requestId) 
        throws IOException {
        
        oos.writeObject(new Wrapper(type, data, requestId, 200));
        oos.flush();
    }

    private static void sendErrorResponse(ObjectOutputStream oos, UUID requestId, int code, String message) {
        try {
            oos.writeObject(new Wrapper((byte) -1, message.getBytes(), requestId, code));
            oos.flush();
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to send error response", e);
        }
    }

    // Configuration getters
    private static String[] getTlsProtocols() {
        return System.getProperty("TLS-PROT-ENF", "TLSv1.2").split(",");
    }

    private static String[] getCipherSuites() {
        return System.getProperty("CIPHERSUITES", "").split(",");
    }

    private static boolean needsClientAuth() {
        return "MUTUAL".equalsIgnoreCase(System.getProperty("TLS-AUTH", "NONE"));
    }

    private static char[] getKeystorePassword() {
        return "authentication_password".toCharArray();
    }

    private static char[] getTruststorePassword() {
        return "authentication_truststore_password".toCharArray();
    }

    // Log formatter
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
}