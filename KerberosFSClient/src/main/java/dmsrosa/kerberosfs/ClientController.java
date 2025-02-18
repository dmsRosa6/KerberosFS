package dmsrosa.kerberosfs;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import java.util.Properties;
import java.util.UUID;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.ClientController.InvalidCommandException;
import dmsrosa.kerberosfs.commands.Command;
import dmsrosa.kerberosfs.commands.CommandTypes;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.handlers.AuthHandler;
import dmsrosa.kerberosfs.handlers.ServiceHandler;
import dmsrosa.kerberosfs.handlers.TGSHandler;
import dmsrosa.kerberosfs.messages.FilePayload;
import dmsrosa.kerberosfs.messages.ResponseAuthenticationMessage;
import dmsrosa.kerberosfs.messages.ResponseServiceMessage;
import dmsrosa.kerberosfs.messages.ResponseTGSMessage;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.Pair;
import dmsrosa.kerberosfs.utils.RandomUtils;

/**
 * ClientController is responsible for processing client commands, performing TLS connections,
 * key exchange, and interacting with the authentication, TGS and service handlers.
 *
 * This version creates an ephemeral SSLSocket for each request and uses a helper (SocketStreams)
 * to lazily open the object streams when they are actually needed. If the socket is found closed,
 * the helper will create a new connection.
 *
 * Note: This code assumes that types like Client, UserInfo, and Authenticator are defined elsewhere.
 */
public class ClientController {
    private static final Logger logger = Logger.getLogger(ClientController.class.getName());
    private static final String TLS_CONFIG_PATH = "/tls-config.properties";
    private static final String TRUSTSTORE_PATH = "/truststore.jks";

    private static SSLContext sslContext;
    private static String[] enabledProtocols;
    private static String[] cipherSuites;

    // Handlers
    private final TGSHandler tgsHandler = new TGSHandler();
    private final ServiceHandler serviceHandler = new ServiceHandler();
    private final AuthHandler authHandler = new AuthHandler();

    // TLS properties loaded from file.
    private final Properties tlsConfig;

    static {
        configureLogger();
        initializeSSLContext();
    }

    public ClientController() {
        this.tlsConfig = loadTLSConfiguration();
        validateTLSConfiguration();
    }

    // --- Logger Configuration ---
    private static void configureLogger() {
        Logger rootLogger = Logger.getLogger("");
        Arrays.stream(rootLogger.getHandlers()).forEach(rootLogger::removeHandler);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new LogFormatter());
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        logger.setLevel(Level.INFO);
    }

    // --- SSL/TLS Initialization ---
    private static void initializeSSLContext() {
        try {
            TrustManagerFactory tmf = createTrustManagerFactory();
            sslContext = SSLContext.getInstance("TLSv1.2");
            // One-way TLS: no key managers needed.
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("SSL context initialization failed", e);
        }
    }

    private static TrustManagerFactory createTrustManagerFactory() throws GeneralSecurityException, IOException {
        KeyStore trustStore = loadTrustStore();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf;
    }

    private static KeyStore loadTrustStore() throws IOException, GeneralSecurityException {
        char[] password = getTruststorePassword();
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = ClientController.class.getResourceAsStream(TRUSTSTORE_PATH)) {
            if (is == null) {
                throw new RuntimeException("Truststore resource not found:" + TRUSTSTORE_PATH);
            }
            ks.load(is, password);
        }
        return ks;
    }

    private static char[] getTruststorePassword() {
        return "Y+kS81NkLbcUPXq3J2PPlg==".toCharArray();
    }

    private Properties loadTLSConfiguration() {
        Properties props = new Properties();
        try (InputStream input = ClientController.class.getResourceAsStream(TLS_CONFIG_PATH)) {
            if (input == null) {
                throw new RuntimeException("TLS configuration resource not found:" + TLS_CONFIG_PATH);
            }
            props.load(input);
            return props;
        } catch (IOException e) {
            throw new RuntimeException("Failed to load TLS configuration", e);
        }
    }

    private void validateTLSConfiguration() {
        enabledProtocols = tlsConfig.getProperty("TLS-PROT-ENF", "TLSv1.2").split(",");
        cipherSuites = tlsConfig.getProperty("CIPHERSUITES", "").split(",");
        if (enabledProtocols.length == 0) {
            throw new IllegalStateException("No TLS protocols configured");
        }
    }

    // --- Command Execution ---
    /**
     * Executes a command by validating its structure and then either handling a login or
     * an authenticated service command.
     */
    public CommandResponse executeCommand(String[] commandParts) throws ClientException,InvalidCommandException {
        validateCommandStructure(commandParts);
        return isLoginCommand(commandParts)
                ? handleLogin(commandParts)
                : processAuthenticatedCommand(commandParts);
    }

    private void validateCommandStructure(String[] commandParts) throws InvalidCommandException {
        if (commandParts == null || commandParts.length == 0) {
            throw new InvalidCommandException("Empty command received");
        }
        CommandTypes type = CommandTypes.fromString(commandParts[0])
                .orElseThrow(() -> new InvalidCommandException("Unknown command: " + commandParts[0]));
        if (commandParts.length - 1 != type.getExpectedArgs()) {
            throw new InvalidCommandException("Invalid number of arguments for command: " + type);
        }
    }

    private boolean isLoginCommand(String[] commandParts) {
        return CommandTypes.LOGIN.name().equalsIgnoreCase(commandParts[0]);
    }

    /**
     * Login: Create an ephemeral connection, perform Diffie–Hellman key exchange,
     * and then authenticate the user.
     */
    private CommandResponse handleLogin(String[] commandParts) throws ClientException {
        String username = commandParts[1];
        String password = commandParts[2];
        SSLSocket socket = null;
        SocketStreams streams = null;
        try {
            socket = createNewSocket();
            socket.setEnabledProtocols(enabledProtocols);
            socket.setEnabledCipherSuites(cipherSuites);
            socket.startHandshake();
            streams = new SocketStreams(socket);
            UUID id = UUID.randomUUID();
            UserInfo userInfo = new UserInfo();
            userInfo.setKeyPassword(password);
            userInfo.setSession(id);
            logger.info("Performing Diffie Hellman key exchange");
            SecretKey dhKey = performDHKeyExchange(streams, id);
            userInfo.setDhKey(dhKey);
            Client.usersInfo.put(username, userInfo);
            logger.info("Authenticating user");
            authenticateUser(streams, username, password, id);
            return new CommandResponse("Login successful", true);
        } catch (Exception e) {
            return new CommandResponse("Login Failed", false);
        } finally {
            if (streams != null) {
                streams.close();
            } else if (socket != null) {
                try { socket.close(); } catch (Exception ex) { }
            }
        }
    }

    /**
     * Modified to use SocketStreams: this method now obtains the streams lazily.
     */
    private void authenticateUser(SocketStreams streams, String username, String password, UUID session) throws ClientException {
        try {
            // Assuming authHandler methods are updated to work with streams.
            authHandler.sendAuthRequest(streams.getOOS(), username, session);
            ResponseAuthenticationMessage response = authHandler.processAuthResponse(streams.getOIS(), username, password);
            logger.info("Auth Response: " + response);
            Client.usersInfo.get(username).setTGT(response);
        } catch (Exception e) {
            throw new ClientException("Authentication failed", e);
        }
    }

    private CommandResponse processAuthenticatedCommand(String[] commandParts) throws ClientException,InvalidCommandException {
        Pair<CommandTypes, Command> commandPair = createCommand(commandParts);
        return executeCommandOverConnection(commandPair.second);
    }

    private Pair<CommandTypes, Command> createCommand(String[] commandParts) throws InvalidCommandException {
        CommandTypes type = CommandTypes.fromString(commandParts[0])
                .orElseThrow(() -> new InvalidCommandException("Invalid command: " + commandParts[0]));
        Command command;
        switch (type) {
            case LOGIN -> throw new InvalidCommandException("Login handled separately");
            case LS, MKDIR -> command = createLsMkdirCommand(type, commandParts);
            case PUT -> command = createPutCommand(type, commandParts);
            case GET, RM, FILE -> command = createFileOperationCommand(type, commandParts);
            case CP -> command = createCpCommand(type, commandParts);
            default -> throw new InvalidCommandException("Invalid Command");
        }
        return new Pair<>(type, command);
    }

    private Command createLsMkdirCommand(CommandTypes type, String[] parts) {
        return new Command(parts[1], parts[2], type);
    }

    private Command createPutCommand(CommandTypes type, String[] parts) {
        if (parts.length < 4) {
            throw new RuntimeException("Missing local or remote file path for PUT command");
        }
        String username = parts[1];
        String localFilePath = parts[2];
        String remoteFilePath = parts[3];  // This is the destination path on the server

        File file = new File(localFilePath);
        if (!file.exists() || !file.isFile()) {
            throw new RuntimeException("Local file does not exist: " + localFilePath);
        }
        try {
            byte[] fileContent = Files.readAllBytes(file.toPath());
            byte[] metaData = createFileMetaData(file.getName(), file.length(), file.lastModified());
            return new Command(username, new FilePayload(metaData, fileContent), remoteFilePath, type);
        } catch (IOException ex) {
            throw new RuntimeException("Failed to read file: " + localFilePath, ex);
        }
    }

    private byte[] createFileMetaData(String fileName, long fileSize, long lastModified) {
        String metaDataString = "FileName: " + fileName + ", Size: " + fileSize + ", LastModified: " + lastModified;
        return metaDataString.getBytes(StandardCharsets.UTF_8);
    }

    private Command createFileOperationCommand(CommandTypes type, String[] parts) {
        if (parts.length < 3) {
            throw new RuntimeException("Missing file path for command: " + parts[0]);
        }
        return new Command(parts[1], parts[2], type);
    }

    private Command createCpCommand(CommandTypes type, String[] parts) {
        if (parts.length < 4) {
            throw new RuntimeException("Missing source or destination path for CP command");
        }
        return new Command(parts[1], null, parts[2], parts[3], type);
    }

    /**
     * Executes the command by first requesting a service ticket and then sending the service command.
     * Uses two ephemeral connections (wrapped in SocketStreams) for TGS and service communication.
     */
    private CommandResponse executeCommandOverConnection(Command command) throws ClientException {
        try {

            Authenticator authenticator = new Authenticator( command.getUsername(), Client.CLIENT_ADDR, command);
            ResponseTGSMessage sgt;
            SocketStreams stream = null;
            
            try {
                SSLSocket tgsSocket = createNewSocket();
                tgsSocket.setEnabledProtocols(enabledProtocols);
                tgsSocket.setEnabledCipherSuites(cipherSuites);
                tgsSocket.startHandshake();
                stream = new SocketStreams(tgsSocket);
                logger.info("Sending request to the access control");
                sgt = requestServiceTicket(stream, command, authenticator);

                Client.usersInfo.get(command.getUsername()).addSGT(command.getCommand().toString(), sgt);
                Pair<Integer, ResponseServiceMessage> response = executeServiceCommand(stream, command, sgt, authenticator);
                
                return new CommandResponse(
                        new String(response.second.getCommandReturn().getPayload(), StandardCharsets.UTF_8),
                        response.first == 200 || response.first == 204? true:false 
                );
            } finally {
                if (stream != null) {
                    stream.close();
                }
            }
        } catch (Exception e) {
            return new CommandResponse(
                        "Command execution failed",
                        false
                );
        }
    }

    private ResponseTGSMessage requestServiceTicket(SocketStreams streams, Command command, Authenticator authenticator)
            throws ClientException {
        try {
            
            ResponseAuthenticationMessage tgt = Client.usersInfo.get(command.getUsername()).getTGT();
            byte[] authData = RandomUtils.serialize(authenticator);
            byte[] cypherauth = CryptoStuff.getInstance().encrypt(tgt.getGeneratedKey(), authData);
            UserInfo userInfo = Client.usersInfo.get(command.getUsername());
            tgsHandler.sendTGSRequest(streams.getOOS(), userInfo.getTGT().getEncryptedTGT(), cypherauth, userInfo.getSessionUUID());
            logger.info("Waiting for access control service response");
            return tgsHandler.processTGSResponse(streams.getOIS(), tgt.getGeneratedKey());
        } catch (Exception e) {
            throw new ClientException("Service ticket request failed", e);
        }
    }

    private Pair<Integer, ResponseServiceMessage> executeServiceCommand(SocketStreams streams, Command command,
                                                         ResponseTGSMessage sgt, Authenticator authenticator)
            throws ClientException {
        try {
             byte[] encryptedAuthenticator = CryptoStuff.getInstance().encrypt(
                    sgt.getSessionKey(),
                    RandomUtils.serialize(authenticator));
            UserInfo userInfo = Client.usersInfo.get(command.getUsername());
            serviceHandler.sendServiceRequest(streams.getOOS(), sgt, encryptedAuthenticator, command, userInfo.getSessionUUID());
            return serviceHandler.processServiceResponse(streams.getOIS(), sgt);
        } catch (Exception e) {
            throw new ClientException("Service command execution failed", e);
        }
    }

    /**
     * Performs Diffie–Hellman key exchange using the provided SocketStreams.
     * Streams are created on demand.
     */
    private SecretKey performDHKeyExchange(SocketStreams streams, UUID sessionId) throws ClientException {
        try {
            KeyPair keyPair = generateDHKeyPair();
            exchangePublicKeys(streams.getOOS(), keyPair, sessionId);
            PublicKey serverKey = receiveServerPublicKey(streams.getOIS());
            return deriveSharedSecret(keyPair, serverKey);
        } catch (GeneralSecurityException | IOException | ClassNotFoundException e) {
            throw new ClientException("Key exchange failed", e);
        }
    }

    private KeyPair generateDHKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Sends the public key inside a Wrapper using the given ObjectOutputStream.
     */
    private void exchangePublicKeys(ObjectOutputStream oos, KeyPair keyPair, UUID sessionId) throws IOException {
        Wrapper keyWrapper = new Wrapper((byte) 0, keyPair.getPublic().getEncoded(), sessionId);
        oos.writeObject(keyWrapper);
        oos.flush();
    }

    /**
     * Reads the server’s public key from the ObjectInputStream.
     */
    private PublicKey receiveServerPublicKey(ObjectInputStream ois)
            throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        Wrapper response = (Wrapper) ois.readObject();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(response.getMessage());
        return KeyFactory.getInstance("DH").generatePublic(keySpec);
    }

    private SecretKey deriveSharedSecret(KeyPair keyPair, PublicKey serverKey)
            throws InvalidKeyException, NoSuchAlgorithmException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(serverKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] derivedKey = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
        return new SecretKeySpec(derivedKey, "AES");
    }

    /**
     * Creates and returns a new SSLSocket connected to Client.DISPATCHER_HOST at Client.DISPATCHER_PORT.
     */
    private SSLSocket createNewSocket() throws IOException {
        return (SSLSocket) sslContext.getSocketFactory().createSocket(Client.DISPATCHER_HOST, Client.DISPATCHER_PORT);
    }

    // --- Utility Classes ---
    private static class LogFormatter extends SimpleFormatter {
        private static final String FORMAT = "[%1$tT.%1$tL] [%2$-7s] %3$s%n";

        @Override
        public String format(LogRecord record) {
            return String.format(FORMAT,
                    new Date(record.getMillis()),
                    record.getLevel().getLocalizedName(),
                    record.getMessage());
        }
    }

    public static class ClientException extends Exception {
        public ClientException(String message) { super(message); }
        public ClientException(String message, Throwable cause) { super(message, cause); }
    }

    public static class InvalidCommandException extends ClientException {
        public InvalidCommandException(String message) { super(message); }
    }

    /**
     * SocketStreams is a helper that wraps an SSLSocket and lazily creates its
     * ObjectOutputStream and ObjectInputStream only when needed.
     * It also checks if the socket is closed and, if so, reopens a new connection.
     */
    private class SocketStreams {
        private SSLSocket socket;
        private ObjectOutputStream oos;
        private ObjectInputStream ois;

        SocketStreams(SSLSocket socket) {
            this.socket = socket;
        }

        /**
         * Checks if the socket is still connected; if not, reopens it.
         */
        private void ensureOpen() throws IOException {
            if (socket == null || socket.isClosed() || !socket.isConnected()) {
                // Reopen the socket.
                socket = createNewSocket();
                socket.setEnabledProtocols(enabledProtocols);
                socket.setEnabledCipherSuites(cipherSuites);
                socket.startHandshake();
                // Reset streams since we are using a new socket.
                oos = null;
                ois = null;
            }
        }

        public ObjectOutputStream getOOS() throws IOException {
            ensureOpen();
            if (oos == null) {
                oos = new ObjectOutputStream(socket.getOutputStream());
                oos.flush();
            }
            return oos;
        }

        public ObjectInputStream getOIS() throws IOException {
            ensureOpen();
            if (ois == null) {
                var a = socket.getInputStream();
                ois = new ObjectInputStream(a);
            }
            return ois;
        }

        /**
         * Closes the streams and the socket.
         */
        public void close() {
            try {
                if (oos != null) {
                    oos.close();
                }
            } catch (Exception e) { }
            try {
                if (ois != null) {
                    ois.close();
                }
            } catch (Exception e) { }
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            } catch (Exception e) { }
        }
    }
}
