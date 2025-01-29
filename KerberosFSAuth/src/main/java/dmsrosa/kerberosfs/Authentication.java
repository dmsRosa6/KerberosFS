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

public class Authentication {
    private static final String FILE_PATH = "users.txt";
    private static Map<String, User> users;
        
            public Authentication() {
                File file = new File(FILE_PATH);
        
                if (file.exists()) {
                    users = readUsers();
            } else {
                users = new HashMap<>();
                try {
                    if (file.createNewFile()) {
                    }
                } catch (IOException e) {
                    throw new IllegalStateException("Failed to create user file at: " + FILE_PATH, e);
                }
            }
        }
    
        public static byte[] getUsernamePassword(String username) {
            if (username == null || username.isEmpty()) {
                return null;
            }
    
            User user = users.get(username);
        if (user == null) {
            return null;
        }
        return user.getHashedPassword();
    }

    public boolean register(String username, String password) {
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            return false;
        }

        if (users.containsKey(username)) {
            return false;
        }
        try {
            User user = new User(username, password);
            users.put(username, user);
            writeUsers();
            return true;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        }
    }

    private void writeUsers() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_PATH))) {
            oos.writeObject(users);
        } catch (IOException e) {
            System.err.println("Error writing user data to file: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, User> readUsers() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE_PATH))) {
            Object obj = ois.readObject();
            if (obj instanceof Map) {
                return (Map<String, User>) obj;
            } else {
                System.err.println("Invalid data format in file. Initializing empty map.");
                return new HashMap<>();
            }
        } catch (EOFException e) {
            System.out.println("User file is empty. Initializing empty map.");
            return new HashMap<>();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error reading user data from file: " + e.getMessage());
            return new HashMap<>();
        }
    }
}
