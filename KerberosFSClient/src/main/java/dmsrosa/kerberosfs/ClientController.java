package dmsrosa.kerberosfs;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.UUID;
import java.util.logging.Level;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.commands.Command;
import dmsrosa.kerberosfs.commands.CommandTypes;
import dmsrosa.kerberosfs.crypto.CryptoException;
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

public class ClientController {

    private final TGSHandler tgshandler;
    private final ServiceHandler serviceHandler;
    private final AuthHandler authHandler;
    private SSLSocket  socket;


    public ClientController() {
        this.tgshandler = new TGSHandler();
        this.serviceHandler = new ServiceHandler();
        this.authHandler = new AuthHandler();
        this.socket = initTLSSocket();
    }

    public CommandTypes validateCommand(String[] parts) throws RuntimeException {
        CommandTypes commandType = Arrays.stream(CommandTypes.values())
                .filter(c -> c.name().equalsIgnoreCase(parts[0]))
                .findFirst()
                .orElse(null);


        if (commandType == null) {
            throw new RuntimeException("No command matches: " + parts[0]);
        }

        if (parts.length - 1 != commandType.getExpectedArgs()) {
            throw new RuntimeException("Number of params doesn't match for: " + parts[0]);
        }

        return commandType;
    }
    
    // Functional interface for `void` operations with exceptions
    @FunctionalInterface
    public interface ConsumerWithException<T> {
        void accept(T t) throws Exception;
    }

    private void processLogin(String username, String password) throws Exception {
        SecretKey key = performDHKeyExchange();
        Client.usersDHKey.putIfAbsent(username, new UserInfo());
        Client.usersDHKey.get(username).setDhKey(key);
        Client.usersDHKey.get(username).setKeyPassword(password);

        requestLogin(username, password);
    }

    private void requestLogin(String clientId, String password) throws Exception {

        if (this.socket == null || this.socket.isClosed()) {
            this.socket = initTLSSocket();
            this.socket.setKeepAlive(true);
        }

        authHandler.sendAuthRequest(socket, clientId);
        Client.usersDHKey.get(clientId).setTGT(authHandler.processAuthResponse(socket, clientId, password));
    }

    public String requestCommand(String[] fullCommand, FilePayload filePayload) throws Exception {
        Client.logger.log(Level.INFO, "Requesting command: " + Arrays.toString(fullCommand));
    
        // Validate command and set up the command object
        Pair<CommandTypes, Command> pair = validateAndSetupCommand(fullCommand, filePayload);
        Client.logger.log(Level.INFO, "Valid Command");
    
        if (pair.first.equals(CommandTypes.LOGIN)) {
            Client.logger.log(Level.INFO, "Doing Login");
            processLogin(fullCommand[1], fullCommand[2]);
            return "Success";
        }
    
        Client.logger.log(Level.INFO, "Executing command");
    
        Command command = pair.second;
        String clientId = command.getUsername();
    
        Authenticator authenticator = new Authenticator(clientId, Client.CLIENT_ADDR, command);
        byte[] authenticatorSerialized = RandomUtils.serialize(authenticator);
    
        reconnectIfNeeded(); // Ensure the socket is valid
        ResponseTGSMessage sgt = requestServiceTicketFromTGS(socket, command, clientId, authenticatorSerialized);
    
        reconnectIfNeeded(); // Ensure the socket is valid
        ResponseServiceMessage response = requestCommandFromService(socket, command, clientId, sgt, authenticatorSerialized);
    
        return Arrays.toString(response.getcommandReturn().getPayload());
    }


    private Pair<CommandTypes, Command> validateAndSetupCommand(String[] fullCommand, FilePayload filePayload) throws Exception {
        CommandTypes commandType = validateCommand(fullCommand);
        Command command;

        switch (commandType) {
            case LOGIN -> command = null;
            case LS, MKDIR -> command = createCommandForLsMkdir(fullCommand, fullCommand[1]);
            case PUT -> command = createCommandForPut(fullCommand, fullCommand[1], filePayload);
            case GET, RM, FILE -> command = createCommandForGetRmFile(fullCommand, fullCommand[1]);
            case CP -> command = createCommandForCp(fullCommand, fullCommand[1]);
            default -> throw new Exception("Command '" + fullCommand[0] + "' is invalid");
        }

        return new Pair<>(commandType, command);
    }

    private ResponseServiceMessage requestCommandFromService(SSLSocket socket, Command command, String clientId, ResponseTGSMessage sgt, byte[] authenticatorSerialized){
        Client.logger.log(Level.INFO, "Requesting service for client " + clientId + "with command " + command.getCommand());
        
        ResponseServiceMessage response = null;
        
        try {
            byte[] encryptedAuthenticator = null;
            reconnectIfNeeded(); // Ensure the socket is valid
    
            encryptedAuthenticator = CryptoStuff.getInstance().encrypt(
                    sgt.getSessionKey(),
                    RandomUtils.serialize(authenticatorSerialized));
    
            serviceHandler.sendServiceRequest(socket, sgt, encryptedAuthenticator, command);
            Client.logger.severe("Waiting Storage response");
            response = serviceHandler.processServiceResponse(socket, sgt);
            Client.logger.info("Finished processing Storage response");
        } catch (IOException e) {
            Client.logger.warning("Socket error: " + e.getMessage());
            this.socket = null; // Force reconnection on next attempt
            throw new RuntimeException("Socket error. Reconnecting...", e);
        } catch (CryptoException | InvalidAlgorithmParameterException ex) {
            Client.logger.warning(ex.getMessage());
            return null;
        }

        return response;
    }

    private ResponseTGSMessage requestServiceTicketFromTGS(SSLSocket socket, Command command, String clientId, byte[] authenticatorSerialized) {
        Client.logger.log(Level.INFO, "Requesting SGT for client " + clientId + "with command " + command.getCommand());
        
        ResponseTGSMessage sgt = null;
    
        try {
            reconnectIfNeeded(); // Ensure the socket is valid
    
            ResponseAuthenticationMessage tgt = Client.usersDHKey.get(clientId).getTGT();
            tgshandler.sendTGSRequest(socket, tgt.getEncryptedTGT(), CryptoStuff.getInstance().encrypt(tgt.getGeneratedKey(), authenticatorSerialized));
    
            Client.logger.severe("Processing TGS response");
            sgt = tgshandler.processTGSResponse(socket, tgt.getGeneratedKey());
            Client.logger.info("Finished processing TGS response");
    
        } catch (IOException e) {
            Client.logger.warning("Socket error: " + e.getMessage());
            this.socket = null; // Force reconnection on next attempt
            throw new RuntimeException("Socket error. Reconnecting...", e);
        } catch (Exception ex) {
            Client.logger.warning(ex.getMessage());
            return null;
        }
    
        Client.usersDHKey.get(clientId).addSGT(command.getCommand(), sgt);
        return sgt;
    }

    private Command createCommandForLsMkdir(String[] fullCommand, String clientId) {
        String path = fullCommand.length == 2 ? "/" : fullCommand[2];
        return new Command(fullCommand[0], clientId, path);
    }

    private Command createCommandForPut(String[] fullCommand, String clientId, FilePayload filePayload) {
        // Validate the local file path
        String localFilePath = fullCommand[2];  // Local file path
        File file = new File(localFilePath);
        if (!file.exists() || !file.isFile()) {
            throw new RuntimeException("Local file does not exist: " + localFilePath);
        }

        // Read the file content as a byte array
        byte[] fileContent = null;
        try {
            fileContent = Files.readAllBytes(file.toPath());
        } catch (IOException ex) {
        }

        // Create the file metadata (example: name, size, and last modified time)
        String fileName = file.getName();
        long fileSize = file.length();
        long lastModified = file.lastModified();

        // Construct the metadata (you can expand this as needed)
        byte[] metaData = createFileMetaData(fileName, fileSize, lastModified);

        // Create the FilePayload with both metadata and file content
        filePayload = new FilePayload(metaData, fileContent);

        // Return the Command object with the remote path, clientId, and the FilePayload
        return new Command(fullCommand[0], clientId, filePayload, fullCommand[1]);  // remote path + file payload
    }

    private byte[] createFileMetaData(String fileName, long fileSize, long lastModified) {
        // Example metadata structure: file name, size, and last modified time
        String metaDataString = "FileName: " + fileName + ", Size: " + fileSize + ", LastModified: " + lastModified;
        return metaDataString.getBytes(StandardCharsets.UTF_8);
    }


    private Command createCommandForGetRmFile(String[] fullCommand, String clientId) {
        return new Command(fullCommand[0], clientId, fullCommand[2]);
    }

    private Command createCommandForCp(String[] fullCommand, String clientId) {
        return new Command(fullCommand[0], clientId, null, fullCommand[2], fullCommand[3]);
    }

    private static SSLSocket initTLSSocket() {
        try {
            // Load truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStoreStream = Client.class.getResourceAsStream(Client.TRUSTSTORE_PATH)) {
                if (trustStoreStream == null) {
                    throw new IOException("Truststore file not found: " + Client.TRUSTSTORE_PATH);
                }
                trustStore.load(trustStoreStream, Client.TRUSTSTORE_PASSWORD);
                Client.logger.info("Truststore loaded successfully.");
            }
    
            // Initialize TrustManagerFactory
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            Client.logger.info("TrustManagerFactory initialized.");
    
            // Create SSLContext
            SSLContext sslContext = SSLContext.getInstance(Client.TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
            Client.logger.info("SSLContext initialized with protocol: " + Client.TLS_VERSION);
    
            // Create and configure SSLSocket
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(Client.DISPATCHER_HOST, Client.DISPATCHER_PORT);
    
            socket.setEnabledProtocols(Client.TLS_PROT_ENF);
            socket.setEnabledCipherSuites(Client.CIPHERSUITES);
            socket.setUseClientMode(!"MUTUAL".equalsIgnoreCase(Client.TLS_AUTH));
            if ("MUTUAL".equalsIgnoreCase(Client.TLS_AUTH)) {
                socket.setNeedClientAuth(true);
                Client.logger.info("Mutual authentication enabled.");
            }
    
            // Start TLS handshake
            Client.logger.info("Starting TLS handshake with dispatcher at " + Client.DISPATCHER_HOST + ":" + Client.DISPATCHER_PORT);
            socket.startHandshake();
            Client.logger.info("TLS handshake successful.");
    
            return socket;
        } catch (IOException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            Client.logger.log(Level.WARNING, "Error initializing TLS socket: ", e);
        }
        return null;
    }
    

    private SecretKey performDHKeyExchange() {
        try {
            if (socket == null || !socket.isConnected()) {
                Client.logger.warning("Socket not connected");
                return null;
            }
    
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
    
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            oos.writeObject(new Wrapper((byte) 0, keyPair.getPublic().getEncoded(), UUID.randomUUID()));
            oos.flush();
    
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            Wrapper response = (Wrapper) ois.readObject();
    
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey receivedPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(response.getMessage()));
    
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(receivedPublicKey, true);
    
            byte[] sharedSecret = keyAgreement.generateSecret();
            if (sharedSecret == null || sharedSecret.length == 0) {
                throw new Exception("Shared secret is null or empty");
            }
    
            byte[] derivedKey = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
            Client.logger.info("Derived key: " + Arrays.toString(derivedKey));
            return new SecretKeySpec(derivedKey, "AES");
    
        } catch (Exception e) {
            Client.logger.log(Level.WARNING, "Error performing DH key exchange: " + e.getMessage());
            e.printStackTrace();
            return null; // Ensure to handle this in the calling code
        }
    }

    private void reconnectIfNeeded() throws IOException {
    int maxRetries = 3;
    int retryCount = 0;

    while (retryCount < maxRetries) {
        if (this.socket == null || this.socket.isClosed()) {
            Client.logger.info("Socket is closed or null. Reconnecting... Attempt " + (retryCount + 1));
            this.socket = initTLSSocket();
            if (this.socket != null) {
                this.socket.setKeepAlive(true); // Enable keep-alive
                return; // Successfully reconnected
            }
            retryCount++;
        } else {
            return; // Socket is already valid
        }
    }

    throw new IOException("Failed to reconnect after " + maxRetries + " attempts.");
}
    
}
