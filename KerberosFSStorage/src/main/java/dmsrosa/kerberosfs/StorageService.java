package dmsrosa.kerberosfs;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.crypto.CryptoException;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.RequestTGSMessage;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class StorageService {
    //Conf
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT = 8083;
    private static final String TLS_CONF_PATH = "/app/tls-config.properties";
    private static final String KEYS_CONF_PATH = "/app/keys.properties";    
    
    // Cryptographic constants
    private static final int KEYSIZE = 256;
    private static final String ALGORITHM = "AES";
    private static SSLContext sslContext;

    private static final Properties tlsConfig = new Properties();
    private static final Properties cryptoConfig = new Properties();


    private static final String FILESYSTEM_PATH = "filesystem";
    private static final String TLS_PROTOCOL = "TLSv1.3";
    
    private static final int TIMEOUT_MS = 10000;
    private FsManager fsManager;

    // Custom logger to print the timestamp in milliseconds
    private static final Logger logger = Logger.getLogger(StorageService.class.getName());

    static {
        initLogger();
        getConfigs();
        initializeSSLContext();
    }


    private static void getConfigs(){
        try (FileInputStream tls = new FileInputStream(TLS_CONF_PATH); FileInputStream keys = new FileInputStream(KEYS_CONF_PATH)) {
            tlsConfig.load(tls);
            cryptoConfig.load(keys);
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

    public void main(String[] args) {
        // Set logger level
        logger.setLevel(Level.SEVERE);
        try {
            fsManager = new FsManager("/");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try (SSLServerSocket serverSocket = createServerSocket()) {
            logger.info("Access control service started on port " + PORT);
            acceptConnections(serverSocket);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start storage service", e.getMessage());
            System.exit(1);
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
        switch (request.getMessageType()) {
            //case 0 -> handleKeyExchange(request, oos);
            case 3 -> processStorageRequest(request, oos);
            //default -> ;
        }
    }

    private static void processStorageRequest(Wrapper request, ObjectOutputStream oos) {
            
            String requestLine;
            String[] parts = null;
            try {
                requestLine = (String) RandomUtils.deserialize(request.getMessage());
    
                parts = requestLine.split(" ", 3);
                if (parts.length < 2) {
                    //oos.write("ERROR: Invalid command format\n");
                    // write a error message
                    oos.flush();
                    return;
                }
            } catch (IOException | ClassNotFoundException ex) {
            }

            String command = parts[0].toUpperCase();
            String path = parts[1];
            String content = parts.length == 3 ? parts[2] : null;

            switch (command) {
                case "GET":
                    String fileContent = fsManager.readFile(path);
                    writer.write(fileContent + "\n");
                    break;
                case "PUT":
                    if (content == null) {
                        writer.write("ERROR: Missing content for PUT\n");
                    } else {
                        fsManager.writeFile(path, content);
                        writer.write("SUCCESS: File saved\n");
                    }
                    break;
                case "DELETE":
                    fsManager.deleteFile(path);
                    writer.write("SUCCESS: File deleted\n");
                    break;
                case "LIST":
                    List<String> files = fsManager.listFolder(path);
                    writer.write(String.join(", ", files) + "\n");
                    break;
                default:
                    writer.write("ERROR: Unknown command\n");
            }
            writer.flush();
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
