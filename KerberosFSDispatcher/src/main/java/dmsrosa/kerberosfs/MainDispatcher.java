package dmsrosa.kerberosfs;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.TimeoutUtils;


public class MainDispatcher {

    public enum ModuleName {
        STORAGE,
        AUTHENTICATION,
        ACCESS_CONTROL
    }

    public static final String KEYSTORE_PASSWORD = "dispatcher_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "dispatcher_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final String TLS_CONFIG = "/app/tls-config.properties";
    public static final int MY_PORT = 8080;
    public static final long TIMEOUT = 20000;

    private static final Properties properties = new Properties();

    static {
        try (FileInputStream input = new FileInputStream(TLS_CONFIG)) {
            properties.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static final String[] TLS_PROT_ENF = properties.getProperty("TLS-PROT-ENF").split(",");
    public static final String[] CIPHERSUITES = properties.getProperty("CIPHERSUITES").split(",");
    public static final String TLS_AUTH_SRV = properties.getProperty("TLS-AUTH-SRV");
    public static final String TLS_AUTH_CLI = properties.getProperty("TLS-AUTH-CLI");

    private static String[] getHostAndPort(ModuleName moduleName) {
        switch (moduleName) {
            case STORAGE:
                return new String[] { "172.17.0.1", "8083" };
            case AUTHENTICATION:
                return new String[] { "172.17.0.1", "8081" };
            case ACCESS_CONTROL:
                return new String[] { "172.17.0.1", "8082" };
            default:
                throw new IllegalArgumentException("Invalid module name");
        }
    }

    // A map from request IDs to client sockets
    private static Map<UUID, SSLSocket> clientSocketMap = new HashMap<>();

    // Custom logger to print the timestamp in milliseconds
    private static final Logger logger = Logger.getLogger(MainDispatcher.class.getName());
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
        } catch (SecurityException e) {
            logger.warning(e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        // Set the log level
        logger.setLevel(Level.INFO);

        // Create a new thread to the client
        initTLSServerSocket();
    }

    private static void initTLSServerSocket() {
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
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(MY_PORT);
            serverSocket.setEnabledProtocols(TLS_PROT_ENF);
            serverSocket.setEnabledCipherSuites(CIPHERSUITES);
            // boolean needAuth = TLS_AUTH_CLI.equals("MUTUAL");
            // serverSocket.setNeedClientAuth(needAuth);

            logger.log(Level.INFO, "Server started on port {0}", MY_PORT);

            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                logger.info("New connection accepted");
                var objectInputStream = new ObjectInputStream(socket.getInputStream());
                Wrapper message = (Wrapper) objectInputStream.readObject();
                logger.log(Level.INFO, "Received request: " + message.toString());
                TimeoutUtils.runWithTimeout(() -> clientHandleRequest(message, socket), TIMEOUT);
            }

        } catch (IOException | ClassNotFoundException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException | TimeoutException e) {
            logger.warning(e.getMessage());
            e.printStackTrace();
        }
    }

    private static void clientHandleRequest(Wrapper request, SSLSocket clientSocket) {
        try {
            // Add the client socket to the map
            clientSocketMap.put(request.getMessageId(), clientSocket);

            SSLSocket socket = initTLSClientSocket(chooseModule(request));

            // Forward the request to the correct socket
            logger.info("Forwarding request to " + chooseModule(request));
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(request);
            objectOutputStream.flush();

            // Get the response from the correct socket
            logger.info("Waiting for response from " + chooseModule(request));
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            Wrapper response = (Wrapper) objectInputStream.readObject();

            // Handle the response
            handleResponse(response);
        } catch (IOException | ClassNotFoundException e) {
            logger.info(e.getMessage());
        }
    }

    private static ModuleName chooseModule(Wrapper request) {
        byte type = request.getMessageType();

        // Choose the correct socket based on the message type
        return switch (type) {
            case 0, 1 -> ModuleName.AUTHENTICATION;
            case 3 -> ModuleName.ACCESS_CONTROL;
            case 6 -> ModuleName.STORAGE;
            default -> {
                System.out.println("Invalid message type: " + type);
                yield null;
            }
        };
    }

    private static void handleResponse(Wrapper response) {
        try {
            // Get the client socket for this response
            SSLSocket clientSocket = clientSocketMap.get(response.getMessageId());
            if (clientSocket == null) {
                // Handle the case where there's no client socket for this response
                System.out.println("No client socket for response: " + response);
                return;
            }
            // Send the response back to the client
            ObjectOutputStream clientOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            clientOutputStream.writeObject(response);
            clientOutputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static SSLSocket initTLSClientSocket(ModuleName module) {
        SSLSocket socket = null;
        try {
            String[] hostAndPort = getHostAndPort(module);

            // KeyStore
            System.out.println("Loading keystore...");
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // TrustStore
            System.out.println("Loading truststore...");
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            System.out.println("Setting up SSL context...");
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Set up the socket to use TLSv1.2
            System.out.println("Setting up socket...");
            socket = (SSLSocket) sslSocketFactory.createSocket(hostAndPort[0], Integer.parseInt(hostAndPort[1]));
            socket.setEnabledProtocols(TLS_PROT_ENF);
            socket.setEnabledCipherSuites(CIPHERSUITES);
            boolean needAuth = TLS_AUTH_SRV.equals("MUTUAL");
            socket.setNeedClientAuth(needAuth);

            // Start the handshake
            System.out.println("Starting handshake...");
            socket.startHandshake();

            return socket;

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException
                | KeyManagementException | UnrecoverableKeyException e) {
            logger.warning(e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

}