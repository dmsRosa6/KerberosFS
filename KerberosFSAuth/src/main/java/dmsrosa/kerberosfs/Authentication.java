package dmsrosa.kerberosfs;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Authentication {
    private static final Logger logger = Logger.getLogger(Authentication.class.getName());
    private static final String FILE_PATH = "users.txt";
    private static Map<String, User> users;
    
    public Authentication() {
        File file = new File(FILE_PATH);

        if (file.exists()) {
            logger.info("User file uploaded");
            users = readUsers();
        } else {
            users = new HashMap<>();
            try {
                if (file.createNewFile()) {
                    logger.info("User file created at: " + FILE_PATH);
                }
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Failed to create user file at: " + FILE_PATH, e);
                throw new IllegalStateException("Failed to create user file", e);
            }
        }
    }

    public byte[] getUsernamePassword(String username) {
        if (username == null || username.isEmpty()) {
            logger.warning("Attempted to retrieve password for an empty or null username.");
            return null;
        }

        User user = users.get(username);
        if (user == null) {
            logger.warning("User not found: " + username);
            return null;
        }
        logger.info("Password retrieved for user: " + username);
        return user.getHashedPassword();
    }

    public boolean register(String username, String password) {
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            logger.warning("Attempted to register with an empty username or password.");
            return false;
        }

        if (users.containsKey(username)) {
            logger.warning("Registration failed: Username already exists - " + username);
            return false;
        }
        
        try {
            User user = new User(username, password);
            users.put(username, user);
            writeUsers();
            logger.info("User registered successfully: " + username);
            return true;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.log(Level.SEVERE, "Error generating password hash for user: " + username, e);
            return false;
        }
    }

    private void writeUsers() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_PATH))) {
            oos.writeObject(users);
            logger.info("User data successfully written to file.");
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error writing user data to file: " + FILE_PATH, e);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, User> readUsers() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE_PATH))) {
            Object obj = ois.readObject();
            if (obj instanceof Map) {
                logger.info("User data successfully read from file.");
                return (Map<String, User>) obj;
            } else {
                logger.warning("Invalid data format in file. Initializing empty map.");
                return new HashMap<>();
            }
        } catch (EOFException e) {
            logger.info("User file is empty. Initializing empty map.");
            return new HashMap<>();
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.SEVERE, "Error reading user data from file: " + FILE_PATH, e);
            return new HashMap<>();
        }
    }
}
