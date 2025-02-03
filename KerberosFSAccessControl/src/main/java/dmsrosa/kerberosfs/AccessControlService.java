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
import java.util.Date;
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
import dmsrosa.kerberosfs.utils.RandomUtils;

public class AccessControlService {

    //Conf
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT = 8082;
    private static final String TLS_CONF_PATH = "/app/tls-config.properties";
    private static final String KEYS_CONF_PATH = "/app/keys.properties";    
    
    // Cryptographic constants
    private static final int KEYSIZE = 256;
    private static final String ALGORITHM = "AES";

    private static SecretKey tgsKey;
    private static SecretKey storageKey;

    private static AccessControl accessControl;
    private static SSLContext sslContext;

    private static final Properties tlsConfig = new Properties();
    private static final Properties keysConfig = new Properties();

    // Custom logger to print the timestamp in milliseconds
    private static final Logger logger = Logger.getLogger(AccessControlService.class.getName());

    static {
        initLogger();
        getConfigs();
        initializeSSLContext();
    }

    public static void main(String[] args) {
        // Set logger level
        logger.setLevel(Level.SEVERE);

        // converting from String to SecretKey
        tgsKey = CryptoStuff.getInstance().convertStringToSecretKey(keysConfig.getProperty("TGS_KEY"));
        storageKey = CryptoStuff.getInstance().convertStringToSecretKey(keysConfig.getProperty("STORAGE_KEY"));
        accessControl = new AccessControl();

        try (SSLServerSocket serverSocket = createServerSocket()) {
            logger.info("Access control service started on port " + PORT);
            acceptConnections(serverSocket);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start access control service", e.getMessage());
            System.exit(1);
        }
    }

    private static void getConfigs(){
        try (FileInputStream tls = new FileInputStream(TLS_CONF_PATH); FileInputStream keys = new FileInputStream(KEYS_CONF_PATH)) {
            tlsConfig.load(tls);
            keysConfig.load(keys);
        } catch (IOException ex) {
            logger.warning(ex.getMessage());
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

            // Initialize KeyManagerFactory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, getKeystorePassword());

            // Initialize TrustManagerFactory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            // Initialize SSLContext
            sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

            logger.info("SSL Context successfully initialized.");

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

    private static void initLogger(){
        try {
            Logger rootLogger = Logger.getLogger("");
            Handler[] handlers = rootLogger.getHandlers();
            if (handlers[0] instanceof ConsoleHandler) {
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
        } catch (Exception e) {
            e.printStackTrace();
        }
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
                //case 0 -> handleKeyExchange(request, oos);
                case 2 -> processAccessControlRequest(request, oos);
                //default -> ;
            }
        } catch (CryptoException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
        }
    }

    private static SSLServerSocket createServerSocket() throws IOException {

        SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory()
            .createServerSocket(PORT);
        
        serverSocket.setEnabledProtocols(getTlsProtocols());
        serverSocket.setEnabledCipherSuites(getCipherSuites());
        serverSocket.setNeedClientAuth(needsClientAuth());
        
        return serverSocket;
    }

    private static void processAccessControlRequest(Wrapper request, ObjectOutputStream oos) throws CryptoException {
        try {   
            // deserialize request message
            RequestTGSMessage requestTGSMessage = (RequestTGSMessage) RandomUtils.deserialize(request.getMessage());
            
            String serviceId = requestTGSMessage.getServiceId();
            byte[] tgtSerialized = requestTGSMessage.getEncryptedTGT();
            byte[] authenticatorSerialized = requestTGSMessage.getEncryptedAuthenticator();
            
            // decrypt and deserialize TGT
            tgtSerialized = CryptoStuff.getInstance().decrypt(tgsKey, tgtSerialized);
            TicketGrantingTicket tgt = (TicketGrantingTicket) RandomUtils.deserialize(tgtSerialized);
            SecretKey keyClientTGS = tgt.getKey();
            
            // decrypt and deserialize authenticator
            authenticatorSerialized = CryptoStuff.getInstance().decrypt(keyClientTGS, authenticatorSerialized);
            Authenticator authenticator = (Authenticator) RandomUtils.deserialize(authenticatorSerialized);
            
            // check if authenticator is valid
            if (!authenticator.isValid(tgt.getClientId(), tgt.getClientAddress())) {
                Wrapper errorWrapper = new Wrapper((byte) 4, null, request.getMessageId(),
                        MessageStatus.UNAUTHORIZED.getCode());
                oos.writeObject(errorWrapper);
            }
            
            Command command = authenticator.getCommand();
            
            // check if the user has permissions for this command
            if (!accessControl.hasPermission(authenticator.getClientId(), command.getCommand())) {
                Wrapper errorWrapper = new Wrapper((byte) 4, null, request.getMessageId(),
                        MessageStatus.UNAUTHORIZED.getCode());
                oos.writeObject(errorWrapper);
                return;
            }
            
            // Checking if the command is valid
            if (!command.isValid()) {
                Wrapper errorWrapper = new Wrapper((byte) 4, null, request.getMessageId(),
                        MessageStatus.FORBIDDEN.getCode());
                oos.writeObject(errorWrapper);
                return;
            }
            
            // generate key for ticket
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEYSIZE);
            SecretKey generatedkey = kg.generateKey();
            
            // create ticket
            ServiceGrantingTicket sgt = new ServiceGrantingTicket(tgt.getClientId(), tgt.getClientAddress(), serviceId,
                    generatedkey, command);
            LocalDateTime issueTime = sgt.getIssueTime();
            
            // serialize the ticket and encrypt it
            byte[] sgtSerialized = RandomUtils.serialize(sgt);
            sgtSerialized = CryptoStuff.getInstance().encrypt(storageKey, sgtSerialized);
            
            // serialize and encrypt message
            byte[] msgSerialized = RandomUtils.serialize(
                    new ResponseTGSMessage(generatedkey, serviceId, issueTime, sgtSerialized));
            msgSerialized = CryptoStuff.getInstance().encrypt(keyClientTGS, msgSerialized);
            
            // create wrapper message
            Wrapper wrapperMessage = new Wrapper((byte) 4, msgSerialized, request.getMessageId(),
                    MessageStatus.OK_NO_CONTENT.getCode());
            
            // send wrapper message
            oos.writeObject(wrapperMessage);

        } catch (IOException | NoSuchAlgorithmException | ClassNotFoundException | InvalidAlgorithmParameterException
                | CryptoException e) {
                logger.warning("Error processing request: " + e.getMessage());
        }
    }

        // Configuration getters
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
            return "ORsksvIlvOj2JeLdAdaUMQ==".toCharArray();
        }
    
        private static char[] getTruststorePassword() {
            return "sZOOqRMTJXh1+yjQhI9qdQ==".toCharArray();
        }

}