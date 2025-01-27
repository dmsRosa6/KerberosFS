package dmsrosa.kerberosfs;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.TimeoutException;
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
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.MessageStatus;
import dmsrosa.kerberosfs.messages.RequestTGSMessage;
import dmsrosa.kerberosfs.messages.ResponseTGSMessage;
import dmsrosa.kerberosfs.messages.ServiceGrantingTicket;
import dmsrosa.kerberosfs.messages.TicketGrantingTicket;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.TimeoutUtils;

import java.time.LocalDateTime;

import dmsrosa.kerberosfs.commands.Command;
import dmsrosa.kerberosfs.crypto.CryptoException;

public class AccessControlService {

    public static final String KEYSTORE_PASSWORD = "access_control_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "access_control_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT_2_DISPATCHER = 8082;
    private static final String KEYS_PATH = "/app/keys.properties";

    private static final String ALGORITHM = "AES";
    private static final int KEYSIZE = 256;

    private static final long TIMEOUT = 10000;

    private static SecretKey tgsKey;
    private static SecretKey storageKey;

    private static SSLServerSocket serverSocket;
    private static AccessControl accessControl;

    private static final Properties properties = new Properties();

    // Custom logger to print the timestamp in milliseconds
    private static final Logger logger = Logger.getLogger(AccessControlService.class.getName());
    static {
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

    static {
        try (FileInputStream input = new FileInputStream("/app/tls-config.properties")) {
            properties.load(input);
        } catch (IOException ex) {
            logger.warning(ex.getMessage());
        }
    }

    public static final String[] TLS_PROT_ENF = properties.getProperty("TLS-PROT-ENF").split(",");
    public static final String[] CIPHERSUITES = properties.getProperty("CIPHERSUITES").split(",");
    public static final String TLS_AUTH = properties.getProperty("TLS-AUTH");

    public static void main(String[] args) {
        // Set logger level
        logger.setLevel(Level.SEVERE);

        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream(KEYS_PATH)) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // converting from String to SecretKey
        tgsKey = CryptoStuff.getInstance().convertStringToSecretKey(props.getProperty("TGS_KEY"));
        System.out.println("TGS key: " + tgsKey);
        storageKey = CryptoStuff.getInstance().convertStringToSecretKey(props.getProperty("STORAGE_KEY"));

        initTLSSocket();
        accessControl = new AccessControl();

        while (true) {
            System.out.println("Server is listening on socket...");
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                TimeoutUtils.runWithTimeout(() -> {
                    try {
                        handleRequest(clientSocket, serverSocket);
                    } catch (CryptoException e) {
                        logger.warning(e.getMessage());
                    }
                }, TIMEOUT);
            } catch (IOException e) {
                logger.warning(e.getMessage());
            } catch (TimeoutException e) {
                logger.warning("Connection timed out.");
            }
        }
    }

    private static void initTLSSocket() {

        try {
            // Keystore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            serverSocket = (SSLServerSocket) sslServerSocketFactory
                    .createServerSocket(PORT_2_DISPATCHER);
            serverSocket.setEnabledProtocols(TLS_PROT_ENF);
            serverSocket.setEnabledCipherSuites(CIPHERSUITES);
            boolean needAuth = TLS_AUTH.equals("MUTUAL");
            serverSocket.setNeedClientAuth(needAuth);

        } catch (IOException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException e) {
            logger.warning(e.getMessage());
        }
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket) throws CryptoException {
        try {
            try ( // Communication logic with the request
                ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream()); ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream())) {
                Wrapper wrapper = (Wrapper) objectInputStream.readObject();
                System.out.println("Received message: " + wrapper);
                
                // deserialize request message
                RequestTGSMessage requestTGSMessage = (RequestTGSMessage) deserializeObject(wrapper.getMessage());
                
                String serviceId = requestTGSMessage.getServiceId();
                byte[] tgtSerialized = requestTGSMessage.getEncryptedTGT();
                byte[] authenticatorSerialized = requestTGSMessage.getEncryptedAuthenticator();
                
                // decrypt and deserialize TGT
                tgtSerialized = CryptoStuff.getInstance().decrypt(tgsKey, tgtSerialized);
                TicketGrantingTicket tgt = (TicketGrantingTicket) deserializeObject(tgtSerialized);
                SecretKey keyClientTGS = tgt.getKey();
                
                // decrypt and deserialize authenticator
                authenticatorSerialized = CryptoStuff.getInstance().decrypt(keyClientTGS, authenticatorSerialized);
                Authenticator authenticator = (Authenticator) deserializeObject(authenticatorSerialized);
                
                // check if authenticator is valid
                if (!authenticator.isValid(tgt.getClientId(), tgt.getClientAddress())) {
                    Wrapper errorWrapper = new Wrapper((byte) 4, null, wrapper.getMessageId(),
                            MessageStatus.UNAUTHORIZED.getCode());
                    objectOutputStream.writeObject(errorWrapper);
                    objectOutputStream.flush();
                    objectOutputStream.close();
                    objectInputStream.close();
                    requestSocket.close();
                }
                
                Command command = authenticator.getCommand();
                
                // check if the user has permissions for this command
                if (!accessControl.hasPermission(authenticator.getClientId(), command.getCommand())) {
                    Wrapper errorWrapper = new Wrapper((byte) 4, null, wrapper.getMessageId(),
                            MessageStatus.UNAUTHORIZED.getCode());
                    objectOutputStream.writeObject(errorWrapper);
                    objectOutputStream.flush();
                    objectOutputStream.close();
                    objectInputStream.close();
                    requestSocket.close();
                    return;
                }
                
                // Checking if the command is valid
                if (!command.isValid()) {
                    Wrapper errorWrapper = new Wrapper((byte) 4, null, wrapper.getMessageId(),
                            MessageStatus.FORBIDDEN.getCode());
                    objectOutputStream.writeObject(errorWrapper);
                    objectOutputStream.flush();
                    objectOutputStream.close();
                    objectInputStream.close();
                    requestSocket.close();
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
                byte[] sgtSerialized = serializeObject(sgt);
                sgtSerialized = CryptoStuff.getInstance().encrypt(storageKey, sgtSerialized);
                
                // serialize and encrypt message
                byte[] msgSerialized = serializeObject(
                        new ResponseTGSMessage(generatedkey, serviceId, issueTime, sgtSerialized));
                msgSerialized = CryptoStuff.getInstance().encrypt(keyClientTGS, msgSerialized);
                
                // create wrapper message
                Wrapper wrapperMessage = new Wrapper((byte) 4, msgSerialized, wrapper.getMessageId(),
                        MessageStatus.OK_NO_CONTENT.getCode());
                
                // send wrapper message
                objectOutputStream.writeObject(wrapperMessage);
                objectOutputStream.flush();
                // closing streams/sockets

            }
            requestSocket.close();

        } catch (IOException | NoSuchAlgorithmException | ClassNotFoundException | InvalidAlgorithmParameterException
                | CryptoException e) {
            e.printStackTrace();
        }
    }

    /* ---- Auxiliary methods ---- */

    private static byte[] serializeObject(Object object) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(object);
            byte[] serializedObject = bos.toByteArray();
            return serializedObject;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Object deserializeObject(byte[] serializedObject) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(serializedObject);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object object = ois.readObject();
            return object;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

}