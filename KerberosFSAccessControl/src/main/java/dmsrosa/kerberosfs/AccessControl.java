package dmsrosa.kerberosfs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import dmsrosa.kerberosfs.commands.CommandTypes;

public class AccessControl {

    private static final String LOCAL_ENCRYPTION_KEY = "LwSIXXbm75btRD3zEDPkWFueMZUxnVxO";
    private static final String ACCESSES_FILE_PATH = "/app/access.conf";

    private final Map<String, String> userPermissions;

    public AccessControl() {
        userPermissions = new HashMap<>();
        if (Files.exists(Paths.get(ACCESSES_FILE_PATH))) {
            loadPermissions();
        } else {
            System.err.println("User permissions file not found: " + ACCESSES_FILE_PATH);
        }
    }

    // Load permissions from the encrypted file
    private void loadPermissions() {
        try {
            byte[] keyBytes = LOCAL_ENCRYPTION_KEY.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] fileContent = Files.readAllBytes(Paths.get(ACCESSES_FILE_PATH));
            byte[] decryptedContent = cipher.doFinal(fileContent);

            String permissions = new String(decryptedContent);
            String[] lines = permissions.split("\n");

            for (String line : lines) {
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    userPermissions.put(parts[0].trim(), parts[1].trim());
                }
            }
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.err.println("Failed to load permissions: " + e.getMessage());
        }
    }

    // Check if a user has permission to execute a specific command
    public boolean hasPermission(String username, String command) {
        String permission = userPermissions.get(username);
        if (permission == null) return false;

        return validatePermission(permission, command.toUpperCase());
    }

    // Validate permission against the command type
    private boolean validatePermission(String permission, String command) {
        if (permission.equals("rw")) return true;

        try {
            CommandTypes commandType = CommandTypes.valueOf(command.toUpperCase());
            if (permission.equals("r") && isReadCommand(commandType)) return true;
            if (permission.equals("w") && isWriteCommand(commandType)) return true;
        } catch (IllegalArgumentException e) {
            // Command not recognized
        }

        return false;
    }

    // Determine if a command is a read command
    private boolean isReadCommand(CommandTypes commandType) {
        return commandType == CommandTypes.LS || commandType == CommandTypes.GET || commandType == CommandTypes.FILE;
    }

    // Determine if a command is a write command
    private boolean isWriteCommand(CommandTypes commandType) {
        return commandType == CommandTypes.MKDIR || commandType == CommandTypes.PUT || commandType == CommandTypes.CP;
    }

    // Get all user permissions (useful for debugging or administrative purposes)
    public Map<String, String> getUserPermissions() {
        return new HashMap<>(userPermissions);
    }
}
