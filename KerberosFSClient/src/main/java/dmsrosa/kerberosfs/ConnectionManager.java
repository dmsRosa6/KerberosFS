package dmsrosa.kerberosfs;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;

final class ConnectionManager {
    private static final Logger logger = Logger.getLogger(ConnectionManager.class.getName());
    
    private final TLSConfig tlsConfig;
    
    ConnectionManager(TLSConfig tlsConfig) {
        this.tlsConfig = tlsConfig;
    }

    public SSLSocket createSocket() throws IOException {
        SSLSocket socket = (SSLSocket) tlsConfig.getSSLContext().getSocketFactory()
                .createSocket(Client.DISPATCHER_HOST, Client.DISPATCHER_PORT);
        socket.setEnabledProtocols(tlsConfig.getEnabledProtocols());
        if (tlsConfig.getCipherSuites() != null) {
            socket.setEnabledCipherSuites(tlsConfig.getCipherSuites());
        }
        return socket;
    }

    public void closeSocket(SSLSocket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ex) {
            logger.log(Level.WARNING, "Error closing socket", ex);
        }
    }
}
