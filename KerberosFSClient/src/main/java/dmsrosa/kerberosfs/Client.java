package dmsrosa.kerberosfs;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.swing.SwingUtilities;

public class Client {

    public static final Logger logger = Logger.getLogger(Client.class.getName());
    static {
        try {
            Logger rootLogger = Logger.getLogger("");
            Handler[] handlers = rootLogger.getHandlers();
            if (handlers.length > 0 && handlers[0] instanceof ConsoleHandler) {
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
            logger.log(Level.WARNING, e.getMessage());
        }
    }

    // Client TLS/SSL configuration constants
    public static final String KEYSTORE_TYPE = "JKS";
    public static final String KEYSTORE_PASSWORD = "client_password";
    public static final String KEYSTORE_PATH = "/keystore.jks";
    public static final String TRUSTSTORE_TYPE = "JKS";
    public static final char[] TRUSTSTORE_PASSWORD = "client_truststore_password".toCharArray();
    public static final String TRUSTSTORE_PATH = "/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final String DISPATCHER_HOST = "localhost";
    public static final int DISPATCHER_PORT = 8080;
    
    public static final String CLIENT_ADDR = "127.0.0.1";
    public static final String TGS_ID = "access_control";
    public static final String SERVICE_ID = "storage_service";
    
    public static final long TIMEOUT = 60000;

    private static final Properties properties = new Properties();
    static {
        try (InputStream input = Client.class.getClassLoader().getResourceAsStream("tls-config.properties")) {
            properties.load(input);
        } catch (IOException ex) {
            logger.log(Level.WARNING, ex.getMessage());
        }
    }
    
    public static Map<String, UserInfo> usersDHKey = new HashMap<>();

    public static final String[] TLS_PROT_ENF = properties.getProperty("TLS-PROT-ENF", "TLSv1.2").split(",");
    public static final String[] CIPHERSUITES = properties.getProperty("CIPHERSUITES", "").split(",");
    public static final String TLS_AUTH = properties.getProperty("TLS-AUTH");

    public static void main(String[] args) {
        SwingUtilities.invokeLater(ClientUI::new);
    }
}
