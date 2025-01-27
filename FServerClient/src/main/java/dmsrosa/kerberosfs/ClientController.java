package dmsrosa.kerberosfs;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
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
import java.security.spec.InvalidKeySpecException;
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
import dmsrosa.kerberosfs.handlers.AuthHandler;
import dmsrosa.kerberosfs.handlers.ServiceHandler;
import dmsrosa.kerberosfs.handlers.TGSHandler;
import dmsrosa.kerberosfs.messages.FilePayload;
import dmsrosa.kerberosfs.messages.ResponseServiceMessage;
import dmsrosa.kerberosfs.messages.ResponseTGSMessage;
import dmsrosa.kerberosfs.utils.Pair;

public class ClientController {

    private final TGSHandler tgshandler;
    private final ServiceHandler serviceHandler;
    private final AuthHandler authHandler;

    public ClientController() {
        this.tgshandler = new TGSHandler();
        this.serviceHandler = new ServiceHandler();
        this.authHandler = new AuthHandler();
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

    @FunctionalInterface
    public interface SupplierWithException<T> {
        T get(SSLSocket socket) throws Exception;
    }

    private <T> T executeWithSocket(SupplierWithException<T> action) throws Exception {
        try (SSLSocket socket = initTLSSocket()) {
            return action.get(socket);
        }
    }

    private void executeWithSocketVoid(ConsumerWithException<SSLSocket> action) throws Exception {
        try (SSLSocket socket = initTLSSocket()) {
            action.accept(socket);
        }
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

        executeWithSocketVoid(socket -> requestLogin(socket, username, password));
    }

    private void requestLogin(SSLSocket socket, String clientId, String password) throws Exception {
        authHandler.sendAuthRequest(socket, clientId);
        Client.usersDHKey.get(clientId).setTGT(authHandler.processAuthResponse(socket, clientId, password));
    }

    public String requestCommand(String[] fullCommand, FilePayload filePayload) throws Exception {
        Client.logger.log(Level.INFO, "Requesting command: " + Arrays.toString(fullCommand));
    
        // Validate command and set up the command object
        Pair<CommandTypes, Command> pair = validateAndSetupCommand(fullCommand, filePayload);
        Client.logger.log(Level.INFO, "Valid Command");
    
        if (pair.getFirst().equals(CommandTypes.LOGIN)) {
            Client.logger.log(Level.INFO, "Doing Login");
            processLogin(fullCommand[1], fullCommand[2]);
            return "Success";
        }
    
        Client.logger.log(Level.INFO, "Executing command");
    
        return executeWithSocket(socket -> {
            Command command = pair.getSecond();
    
            // Request SGT from TGS
            ResponseTGSMessage sgt = requestServiceTicketFromTGS(socket, command, fullCommand[1]);
    
            // Establish a service connection and send the request
            serviceHandler.sendServiceRequest(socket, command, sgt);
    
            // Wait for the server response and process it
            ResponseServiceMessage response = serviceHandler.processServiceResponse(socket, sgt);
    
            return Arrays.toString(response.getcommandReturn().getPayload());
        });
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

    private ResponseTGSMessage requestServiceTicketFromTGS(SSLSocket socket, Command command, String clientId) throws Exception {
        Client.logger.log(Level.INFO, "Requesting SGT for client {0} with command {1}", new Object[]{clientId, command.getCommand()});

        Authenticator authenticator = new Authenticator(clientId, Client.CLIENT_ADDR, command);
        byte[] authenticatorSerialized = Utils.serialize(authenticator);

        ResponseAuthenticationMessage tgt = Client.usersDHKey.get(clientId).getTGT();
        tgshandler.sendTGSRequest(socket, tgt.getEncryptedTGT(),
                CryptoStuff.getInstance().encrypt(tgt.getGeneratedKey(), authenticatorSerialized),
                command);

        ResponseTGSMessage sgt = tgshandler.processTGSResponse(socket, tgt.getGeneratedKey());
        Client.usersDHKey.get(clientId).addSGT(command.getCommand(), sgt);
        return sgt;
    }

    private Command createCommandForLsMkdir(String[] fullCommand, String clientId) {
        String path = fullCommand.length == 2 ? "/" : fullCommand[2];
        return new Command(fullCommand[0], clientId, path);
    }

    private Command createCommandForPut(String[] fullCommand, String clientId, FilePayload filePayload) {
        return new Command(fullCommand[0], clientId, filePayload, fullCommand[2]);
    }

    private Command createCommandForGetRmFile(String[] fullCommand, String clientId) {
        return new Command(fullCommand[0], clientId, fullCommand[2]);
    }

    private Command createCommandForCp(String[] fullCommand, String clientId) {
        return new Command(fullCommand[0], clientId, null, fullCommand[2], fullCommand[3]);
    }

    private static SSLSocket initTLSSocket() {
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStoreStream = Client.class.getResourceAsStream(Client.TRUSTSTORE_PATH)) {
                if (trustStoreStream == null) {
                    throw new IOException("Truststore file not found: " + Client.TRUSTSTORE_PATH);
                }
                trustStore.load(trustStoreStream, Client.TRUSTSTORE_PASSWORD);
            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance(Client.TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(Client.DISPATCHER_HOST, Client.DISPATCHER_PORT);

            socket.setEnabledProtocols(Client.TLS_PROT_ENF);
            socket.setEnabledCipherSuites(Client.CIPHERSUITES);
            socket.setUseClientMode(!"MUTUAL".equalsIgnoreCase(Client.TLS_AUTH));
            if ("MUTUAL".equalsIgnoreCase(Client.TLS_AUTH)) {
                socket.setNeedClientAuth(true);
            }

            socket.startHandshake();
            return socket;
        } catch (IOException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            Client.logger.log(Level.WARNING, "Error initializing TLS socket: ", e);
        }
        return null;
    }

    private SecretKey performDHKeyExchange() {
        try (SSLSocket socket = initTLSSocket()) {
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
            byte[] derivedKey = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
            return new SecretKeySpec(derivedKey, "AES");

        } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            Client.logger.log(Level.WARNING, "Error performing DH key exchange: ", e);
        }
        return null;
    }
}
