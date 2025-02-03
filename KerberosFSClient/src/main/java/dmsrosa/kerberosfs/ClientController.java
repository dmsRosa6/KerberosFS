package dmsrosa.kerberosfs;

import java.io.File;
import java.io.FileInputStream;
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
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
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

public class ClientController {
    private static final Logger logger = Logger.getLogger(ClientController.class.getName());
    
    // Configuration constants
    private static final String TLS_CONFIG_PATH = "/app/tls-config.properties";
    private static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private static final int MAX_RECONNECT_ATTEMPTS = 3;
    private static final int RECONNECT_BASE_DELAY_MS = 1000;
    
    // TLS configuration
    private static SSLContext sslContext;
    private static String[] enabledProtocols;
    private static String[] cipherSuites;
    
    // Client components
    private final TGSHandler tgsHandler = new TGSHandler();
    private final ServiceHandler serviceHandler = new ServiceHandler();
    private final AuthHandler authHandler = new AuthHandler();
    private SSLSocket socket;
    private final Properties tlsConfig;

    static {
        configureLogger();
        initializeSSLContext();
    }

    public ClientController() {
        this.tlsConfig = loadTLSConfiguration();
        validateTLSConfiguration();
    }

    private static void configureLogger() {
        Logger rootLogger = Logger.getLogger("");
        Arrays.stream(rootLogger.getHandlers()).forEach(rootLogger::removeHandler);
        
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new LogFormatter());
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        logger.setLevel(Level.INFO);
    }

    private static void initializeSSLContext() {
        try {
            TrustManagerFactory tmf = createTrustManagerFactory();
            sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("SSL context initialization failed", e);
        }
    }

    private static TrustManagerFactory createTrustManagerFactory() 
        throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        
        KeyStore trustStore = null;
        try {
            trustStore = loadTrustStore();
        } catch (GeneralSecurityException ex) {
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(trustStore);
        return tmf;
    }

    private static KeyStore loadTrustStore() throws IOException, GeneralSecurityException {
        char[] password = getTruststorePassword();
        try (InputStream is = new FileInputStream(TRUSTSTORE_PATH)) {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(is, password);
            return ks;
        }
    }

    private static char[] getTruststorePassword() {
        String envPassword = System.getenv("TRUSTSTORE_PASSWORD");
        if (envPassword == null || envPassword.isEmpty()) {
            throw new SecurityException("Truststore password not configured");
        }
        return envPassword.toCharArray();
    }

    private Properties loadTLSConfiguration() {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream(TLS_CONFIG_PATH)) {
            props.load(input);
            return props;
        } catch (IOException e) {
            throw new RuntimeException("Failed to load TLS configuration", e);
        }
    }

    private void validateTLSConfiguration() {
        enabledProtocols = tlsConfig.getProperty("TLS-PROT-ENF", "TLSv1.2")
            .split(",");
        cipherSuites = tlsConfig.getProperty("CIPHERSUITES", "")
            .split(",");
        
        if (enabledProtocols.length == 0) {
            throw new IllegalStateException("No TLS protocols configured");
        }
    }

    public CommandResponse executeCommand(String[] commandParts) throws ClientException {
        try {
            validateCommandStructure(commandParts);
            
            if (isLoginCommand(commandParts)) {
                return handleLogin(commandParts);
            }
            
            return processAuthenticatedCommand(commandParts);
        } catch (ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new ClientException("Command execution failed", e);
        }
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

    private CommandResponse handleLogin(String[] commandParts) throws ClientException {
        try {
            String username = commandParts[1];
            String password = commandParts[2];
            
            SecretKey dhKey = performDHKeyExchange();
            storeUserCredentials(username, password, dhKey);
            
            authenticateUser(username, password);
            return new CommandResponse("Login successful", true);
        } catch (Exception e) {
            throw new ClientException("Login failed", e);
        }
    }

    private void storeUserCredentials(String username, String password, SecretKey dhKey) {
        UserInfo userInfo = new UserInfo();
        userInfo.setDhKey(dhKey);
        userInfo.setKeyPassword(password);
        Client.usersDHKey.put(username, userInfo);
    }

    private void authenticateUser(String username, String password) throws ClientException {
        try {
            reconnectIfNeeded();
            authHandler.sendAuthRequest(socket, username);
            ResponseAuthenticationMessage response = authHandler.processAuthResponse(
                socket, 
                username,
                password
            );
            Client.usersDHKey.get(username).setTGT(response);
        } catch (Exception e) {
            throw new ClientException("Authentication failed", e);
        }
    }

    private CommandResponse processAuthenticatedCommand(String[] commandParts) 
        throws ClientException {
        
        try {
            Pair<CommandTypes, Command> commandPair = createCommand(commandParts);
            return executeCommand(commandPair.second);
        } catch (ClientException e) {
            throw new ClientException("Command processing failed", e);
        }
    }

    private Pair<CommandTypes, Command> createCommand(String[] commandParts) 
            throws InvalidCommandException {
        
        if (commandParts.length == 0) {
            throw new InvalidCommandException("Command cannot be empty");
        }

        Optional<CommandTypes> c = CommandTypes.fromString(commandParts[0]);
        Command command = null;
        FilePayload filePayload = null;
        switch (c.get()) {
            case LOGIN -> command = null;
            case LS, MKDIR -> command = createCommandForLsMkdir(commandParts, commandParts[1]);
            case PUT -> command = createCommandForPut(commandParts, commandParts[1], filePayload);
            case GET, RM, FILE -> command = createCommandForGetRmFile(commandParts, commandParts[1]);
            case CP -> command = createCommandForCp(commandParts, commandParts[1]);
            default -> throw new InvalidCommandException("Unknown command type: " + commandParts[0]);
        }

        return new Pair<>(c.get(), command);
    }

    private Command createCommandForLsMkdir(String[] fullCommand, String clientId) {
        String path = fullCommand.length == 2 ? "/" : fullCommand[2];
        return new Command(fullCommand[0], clientId, path);
    }

    private Command createCommandForPut(String[] fullCommand, String clientId, FilePayload filePayload) {
        if (fullCommand.length < 3) {
            throw new RuntimeException("Missing local file path for PUT command");
        }

        String localFilePath = fullCommand[2];  
        File file = new File(localFilePath);
        if (!file.exists() || !file.isFile()) {
            throw new RuntimeException("Local file does not exist: " + localFilePath);
        }

        byte[] fileContent;
        try {
            fileContent = Files.readAllBytes(file.toPath());
        } catch (IOException ex) {
            throw new RuntimeException("Failed to read file: " + localFilePath, ex);
        }

        byte[] metaData = createFileMetaData(file.getName(), file.length(), file.lastModified());
        filePayload = new FilePayload(metaData, fileContent);

        return new Command(fullCommand[0], clientId, filePayload, fullCommand[1]);
    }

    private byte[] createFileMetaData(String fileName, long fileSize, long lastModified) {
        String metaDataString = "FileName: " + fileName + ", Size: " + fileSize + ", LastModified: " + lastModified;
        return metaDataString.getBytes(StandardCharsets.UTF_8);
    }

    private Command createCommandForGetRmFile(String[] fullCommand, String clientId) {
        if (fullCommand.length < 3) {
            throw new RuntimeException("Missing file path for command: " + fullCommand[0]);
        }
        return new Command(fullCommand[0], clientId, fullCommand[2]);
    }

    private Command createCommandForCp(String[] fullCommand, String clientId) {
        if (fullCommand.length < 4) {
            throw new RuntimeException("Missing source or destination path for CP command");
        }
        return new Command(fullCommand[0], clientId, null, fullCommand[2], fullCommand[3]);
    }


    private CommandResponse executeCommand(Command command) throws ClientException {
        try {
            reconnectIfNeeded();
            
            Authenticator authenticator = createAuthenticator(command);
            ResponseTGSMessage sgt = requestServiceTicket(command, authenticator);
            ResponseServiceMessage response = executeServiceCommand(command, sgt, authenticator);
            
            return new CommandResponse(
                Arrays.toString(response.getCommandReturn().getPayload()),
                true
            );
        } catch (Exception e) {
            throw new ClientException("Command execution failed", e);
        }
    }

    private Authenticator createAuthenticator(Command command) {
        return new Authenticator(
            command.getUsername(),
            Client.CLIENT_ADDR,
            command
        );
    }

    private ResponseTGSMessage requestServiceTicket(Command command, Authenticator authenticator) 
        throws ClientException, Exception {
        
        try {
            byte[] authenticatorData = RandomUtils.serialize(authenticator);
            UserInfo userInfo = Client.usersDHKey.get(command.getUsername());
            
            tgsHandler.sendTGSRequest(
                socket,
                userInfo.getTGT().getEncryptedTGT(),
                authenticatorData
            );

            return tgsHandler.processTGSResponse(socket, userInfo.getKeyPassword());
        } catch (IOException e) {
            throw new ClientException("Service ticket request failed", e);
        }
    }

    private ResponseServiceMessage executeServiceCommand(Command command, 
            ResponseTGSMessage sgt, Authenticator authenticator) throws ClientException {
        
        try {
            byte[] authenticatorData = RandomUtils.serialize(authenticator);
            serviceHandler.sendServiceRequest(
                socket,
                sgt,
                authenticatorData,
                command
            );

            return serviceHandler.processServiceResponse(socket, sgt);
        } catch (Exception e) {
            throw new ClientException("Service command execution failed", e);
        }
    }

    private SecretKey performDHKeyExchange() throws ClientException {
        try {
            reconnectIfNeeded();
            
            KeyPair keyPair = generateDHKeyPair();
            exchangePublicKeys(keyPair);
            PublicKey serverKey = receiveServerPublicKey();
            
            return deriveSharedSecret(keyPair, serverKey);
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ClientException("Key exchange failed", e);
        }
    }

    private KeyPair generateDHKeyPair() throws NoSuchAlgorithmException, 
        InvalidAlgorithmParameterException {
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private void exchangePublicKeys(KeyPair keyPair) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            Wrapper keyWrapper = new Wrapper(
                (byte) 0, 
                keyPair.getPublic().getEncoded(), 
                UUID.randomUUID()
            );
            oos.writeObject(keyWrapper);
        }
    }

    private PublicKey receiveServerPublicKey() throws IOException, ClassNotFoundException, 
        NoSuchAlgorithmException, InvalidKeySpecException {
        
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            Wrapper response = (Wrapper) ois.readObject();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(response.getMessage());
            return KeyFactory.getInstance("DH").generatePublic(keySpec);
        }
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

    private synchronized void reconnectIfNeeded() throws IOException {
        if (isConnectionValid()) return;

        int attempt = 0;
        while (attempt < MAX_RECONNECT_ATTEMPTS) {
            try {
                attempt++;
                logger.info("Connection attempt " + attempt + "/" + MAX_RECONNECT_ATTEMPTS);
                establishNewConnection();
                return;
            } catch (IOException e) {
                handleReconnectError(attempt, e);
            }
        }
        throw new IOException("Failed to connect after " + MAX_RECONNECT_ATTEMPTS + " attempts");
    }

    private boolean isConnectionValid() {
        return socket != null && 
               !socket.isClosed() && 
               socket.isConnected() &&
               !socket.isInputShutdown() &&
               !socket.isOutputShutdown();
    }

    private void establishNewConnection() throws IOException {
        closeExistingConnection();
        socket = createNewSocket();
        socket.startHandshake();
        logger.info("Successfully connected to dispatcher");
    }

    private void closeExistingConnection() {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                logger.warning("Error closing socket: " + e.getMessage());
            }
        }
    }

    private SSLSocket createNewSocket() throws IOException {
        SSLSocket newSocket = (SSLSocket) sslContext.getSocketFactory()
            .createSocket(Client.DISPATCHER_HOST, Client.DISPATCHER_PORT);
        
        newSocket.setEnabledProtocols(enabledProtocols);
        newSocket.setEnabledCipherSuites(cipherSuites);
        newSocket.setKeepAlive(true);
        return newSocket;
    }

    private void handleReconnectError(int attempt, IOException e) throws IOException {
        logger.log(Level.WARNING, "Connection attempt failed: " + e.getMessage());
        
        try {
            Thread.sleep((long) (RECONNECT_BASE_DELAY_MS * Math.pow(2, attempt)));
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Reconnection interrupted", ie);
        }
        
        if (attempt == MAX_RECONNECT_ATTEMPTS) {
            throw new IOException("Final reconnection attempt failed", e);
        }
    }

    // Utility classes
    private static class LogFormatter extends SimpleFormatter {
        private static final String FORMAT = "[%1$tT.%1$tL] [%2$-7s] [%3$s] %4$s%n";

        @Override
        public String format(LogRecord record) {
            return String.format(FORMAT,
                new Date(record.getMillis()),
                record.getLevel().getLocalizedName(),
                record.getLoggerName(),
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

    public static class CommandResponse {
        private final String result;
        private final boolean success;

        public CommandResponse(String result, boolean success) {
            this.result = result;
            this.success = success;
        }

        // Getters
        public String getResult() { return result; }
        public boolean isSuccess() { return success; }
    }
}