package dmsrosa.kerberosfs;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import dmsrosa.kerberosfs.MainDispatcher.ModuleName;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.TimeoutUtils;

public class MainDispatcher {

    private static final Logger logger = Logger.getLogger(MainDispatcher.class.getName());
    private static Map<String, SSLSocket> services;
    private static SSLServerSocket socket;
    private static SSLContext context;
    
    // Configuration
    private static final Properties tlsConfig = new Properties();
    private static final String KEYSTORE_PATH = "/app/keystore.jks";
    private static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    private static final String TLS_CONFIG = "/app/tls-config.properties";
    private static final int SERVER_PORT = 8080;
    private static final long REQUEST_TIMEOUT = 20000;
    
    public enum ModuleName {
        STORAGE, AUTHENTICATION, ACCESS_CONTROL
    }

    static {
        loadTlsConfiguration();
    }

    public static void main(String[] args) {
        logger.info("Starting MainDispatcher server");
        services = new HashMap<>();


        try {
            context = createSSLContext();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException | KeyManagementException ex) {
            logger.warning("Error while initializing context:" + ex.getMessage());
        }

        try {
            initServerSocket();
            initServicesClientSockets();
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Fatal server error initialing" +  e.getMessage());
            System.exit(1);
        }

        configureServerSocket(socket);

        try{
            startServerLoop(socket);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error in server loop", e);
        } finally {
            try {
                socket.close();
            } catch (IOException ex) {
                logger.log(Level.WARNING, "Error closing server socket", ex);
            }
        }
        
    }

    private static void loadTlsConfiguration() {
        try (InputStream input = new FileInputStream(TLS_CONFIG)) {
            tlsConfig.load(input);
            logger.info("Loaded TLS configuration");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load TLS configuration", e);
        }
    }


    /**
     * 
     * Socket related functions
     *  
     */


    private static void initServicesClientSockets() throws IOException{
        SSLSocketFactory factory = context.getSocketFactory();

        for(ModuleName m: ModuleName.values()){
            String[] host_port = getModuleAddress(m);
            SocketAddress address = new InetSocketAddress(host_port[0], Integer.parseInt(host_port[1]));
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.connect(address, 5000); // 5 seconds timeout
            services.put(m.toString(), socket);
        }
    }

    private static void initServerSocket() throws IOException {
        SSLServerSocketFactory factory = context.getServerSocketFactory();

        socket = (SSLServerSocket) factory.createServerSocket(SERVER_PORT);
    }

    private static SSLContext createSSLContext() throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
        
                KeyStore keyStore = KeyStore.getInstance("JKS");

        try (InputStream ksIs = new FileInputStream(KEYSTORE_PATH)) {
            keyStore.load(ksIs, getKeystorePassword());
        }
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, getKeystorePassword());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream tsIs = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(tsIs, getTruststorePassword());
        }
        
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance(getTlsVersion());
        
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        
        return sslContext;
    }


    private static void configureServerSocket(SSLServerSocket serverSocket) {
        serverSocket.setEnabledProtocols(getEnabledProtocols());
        serverSocket.setEnabledCipherSuites(getCipherSuites());
        serverSocket.setNeedClientAuth(needsClientAuth());
        logger.info(() -> String.format("Server configured with protocols: %s, ciphers: %s",
                Arrays.toString(getEnabledProtocols()), Arrays.toString(getCipherSuites())));
    }

    private static void closeSocketSilently(SSLSocket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error closing socket", e);
        }
    }

    private static void forwardRequestToModule(Wrapper request, SSLSocket moduleSocket) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(moduleSocket.getOutputStream())) {
            oos.writeObject(request);
        }
    }

    private static Wrapper receiveModuleResponse(SSLSocket moduleSocket) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(moduleSocket.getInputStream())) {
            return (Wrapper) ois.readObject();
        }
    }
    
    private static void forwardResponseToClient(SSLSocket clientSocket, Wrapper response) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream())) {
            oos.writeObject(response);
        }
    }
    
    /**
     * 
     * Dispatcher request handlding
     * 
     */


    private static void startServerLoop(SSLServerSocket serverSocket) {
        logger.info(() -> "Server listening on port " + serverSocket.getLocalPort());
        
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                handleClientConnection(clientSocket);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error accepting client connection", e);
            }
        }
    }

   private static void handleClientConnection(SSLSocket clientSocket) {
        try {
            logger.info(() -> "New client connection from: " + clientSocket.getRemoteSocketAddress());
            clientSocket.startHandshake();

            TimeoutUtils.runWithTimeout(() -> {
                try (ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream())) {
                    Wrapper request = (Wrapper) ois.readObject();
                    processClientRequest(clientSocket, request);
                } catch (IOException | ClassNotFoundException e) {
                    logger.log(Level.WARNING, "Error processing client request", e);
                    throw new CompletionException("Request handling failed", e);
                }
            }, REQUEST_TIMEOUT);
            
        } catch (TimeoutException e) {
            logger.warning("Request processing timed out");
            sendErrorResponse(clientSocket, 504, "Gateway Timeout");
        } catch (CompletionException e) {
            logger.log(Level.WARNING, "Failed to process client request", e.getCause());
            sendErrorResponse(clientSocket, 500, "Internal Server Error");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Unexpected error handling client connection", e);
        } finally {
            closeSocketSilently(clientSocket);
            logger.info("Client connection closed");
        }
        }

        private static void sendErrorResponse(SSLSocket socket, int errorCode, String message) {
        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            oos.writeObject(new Wrapper((byte) errorCode, message.getBytes(), UUID.randomUUID()));
        } catch (IOException e) {
            logger.log(Level.FINE, "Failed to send error response", e);
        }
        }

    private static void processClientRequest(SSLSocket clientSocket, Wrapper request) {
        try {
            ModuleName targetModule = resolveTargetModule(request);
            logger.info(() -> String.format("Routing request %s to %s", request.getMessageId(), targetModule));
            
            SSLSocket s = services.get(targetModule.toString());
            forwardRequestToModule(request, s);
            Wrapper response = receiveModuleResponse(s);
            forwardResponseToClient(clientSocket, response);
            
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Request processing failed", e);
            throw new RuntimeException("Request processing error", e);
        }
    }

    private static ModuleName resolveTargetModule(Wrapper request) {
        return switch (request.getMessageType()) {
            case 0, 1 -> ModuleName.AUTHENTICATION;
            case 3 -> ModuleName.ACCESS_CONTROL;
            case 6 -> ModuleName.STORAGE;
            default -> throw new IllegalArgumentException("Invalid message type: " + request.getMessageType());
        };
    }

    private static String[] getModuleAddress(ModuleName module) {
        return tlsConfig.getProperty(module.toString()).split(":");
    }    

    /**
     * Getters
     */

    private static String[] getEnabledProtocols() {
        return tlsConfig.getProperty("TLS-PROT-ENF", "TLSv1.2").split(",");
    }

    private static String[] getCipherSuites() {
        return tlsConfig.getProperty("CIPHERSUITES", "").split(",");
    }

    private static boolean needsClientAuth() {
        return "MUTUAL".equalsIgnoreCase(tlsConfig.getProperty("TLS-AUTH-SRV", "NONE"));
    }

    private static char[] getKeystorePassword() {
        return "dbrCOv9mnfR22RqlM6HbmA==".toCharArray();
    }

    private static char[] getTruststorePassword() {
        return "Eod62hGNQNLEgqTIadv93w==".toCharArray();
    }

    private static String getTlsVersion() {
        return tlsConfig.getProperty("TLS_VERSION", "TLSv1.2");
    }
}
