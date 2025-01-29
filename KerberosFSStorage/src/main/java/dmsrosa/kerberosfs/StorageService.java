package dmsrosa.kerberosfs;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class StorageService {
    private static final String FILESYSTEM_PATH = "filesystem";
    private static final String TLS_PROTOCOL = "TLSv1.3";
    private static final int PORT = 8083;
    private static final int TIMEOUT_MS = 10000;

    public static void main(String[] args) {
        try {
            FsManager fsManager = new FsManager(FILESYSTEM_PATH);
            SSLServerSocketFactory factory = createSSLServerSocketFactory();
            
            try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT)) {
                serverSocket.setNeedClientAuth(true);

                while (true) {
                    try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {
                        clientSocket.setSoTimeout(TIMEOUT_MS);
                        handleClientRequest(clientSocket, fsManager);
                    } catch (IOException e) {
                    }
                }
            }
        } catch (Exception e) {
        }
    }
    
    private static SSLServerSocketFactory createSSLServerSocketFactory() throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream keyStoreStream = new FileInputStream("keystore.jks")) {
                keyStore.load(keyStoreStream, "password".toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, "password".toCharArray());
            SSLContext context = SSLContext.getInstance(TLS_PROTOCOL);
            context.init(kmf.getKeyManagers(), null, new SecureRandom());
            return context.getServerSocketFactory();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            throw new Exception("Failed to initialize SSL configuration");
        }
    }

    private static void handleClientRequest(SSLSocket clientSocket, FsManager fsManager) {
        String clientAddress = clientSocket.getInetAddress().getHostAddress();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))) {
            
            String requestLine = reader.readLine();
            if (requestLine == null || requestLine.trim().isEmpty()) {
                return;
            }

            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 2) {
                writer.write("ERROR: Invalid command format\n");
                writer.flush();
                return;
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
        } catch (IOException e) {
        }
    }
}
