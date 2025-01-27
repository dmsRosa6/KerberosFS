package org.example;

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
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.example.utils.User;

public class Authentication {
    private static final String FILE_PATH = "users.txt"; 
    private final Map<String, User> users;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public Authentication() {
        File file = new File(FILE_PATH);
    
        if (file.exists()) {
            users = readUsers();
            for(User u : users.values()){
                AuthenticationService.logger.warning(u.getUsername());
            }
        } else {
            users = new HashMap<>();
            try {
                if (file.createNewFile()) {
                    System.out.println("User file created at: " + FILE_PATH);
                }
            } catch (IOException e) {
                throw new IllegalStateException("Failed to create user file at: " + FILE_PATH, e);
            }
        }
    }
    

    public byte[] getUsernamePassword(String username) {
        if (username == null || username.isEmpty()) {
            return null;
        }

        lock.readLock().lock();
        try {
            User user = users.get(username);
            if (user == null) {
                return null;
            }
            return user.getHashedPassword();
        } catch (Exception e) {
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean register(String username, String password) {
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            return false;
        }

        lock.writeLock().lock();
        try {
            if (users.containsKey(username)) {
                return false;
            }
            User user = new User(username, password);
            users.put(username, user);
            writeUsers();
            return true;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void writeUsers() {
        lock.writeLock().lock();
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_PATH))) {
            oos.writeObject(users);
        } catch (IOException e) {
        } finally {
            lock.writeLock().unlock();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, User> readUsers() {
        lock.readLock().lock();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE_PATH))) {
            Object obj = ois.readObject();
            AuthenticationService.logger.warning(obj.toString());
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
        } finally {
            lock.readLock().unlock();
        }
    }
    

}