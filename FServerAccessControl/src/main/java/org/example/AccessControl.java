package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;

public class AccessControl {

    private static final String LOCAL_ENCRYPTION_KEY = "LwSIXXbm75btRD3zEDPkWFueMZUxnVxO";
    private static final String ACCESSES_FILE_PATH = "/app/access.conf";

    private Map<String, String> userPermissions;

    private enum ReadCommands {
        LS, GET, FILE
    }

    private enum WriteCommands {
        MKDIR, PUT, CP
    }

    public AccessControl() {
        userPermissions = new HashMap<>();
        loadPermissions();
    }

    // This method is used to pre-install users in the file.
    private void loadPermissions() {
        try {
            byte[] keyBytes = LOCAL_ENCRYPTION_KEY.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] fileContent;
            try (InputStream is = new FileInputStream(ACCESSES_FILE_PATH);
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
                int nRead;
                byte[] data = new byte[1024];
                while ((nRead = is.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                buffer.flush();
                fileContent = buffer.toByteArray();
            }

            byte[] decryptedContent = cipher.doFinal(fileContent);

            String permissions = new String(decryptedContent);
            String[] lines = permissions.split("\n");

            for (String line : lines) {
                String[] parts = line.split(":");
                userPermissions.put(parts[0].trim(), parts[1].trim());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // This method is used to check the accesses of the users in the system.
    public boolean hasPermission(String username, String command) {
        String permission = userPermissions.get(username);
        if (permission == null)
            return false;

        return validatePermission(permission, command.toUpperCase());
    }

    // This method is used to check the accesses of the users in the system.
    private boolean validatePermission(String permission, String command) {
        if (permission.equals("rw"))
            return true;

        if (permission.equals("r")) {
            for (ReadCommands readCommand : ReadCommands.values()) {
                if (command.equalsIgnoreCase(readCommand.name()))
                    return true;
            }
        } else if (permission.equals("w")) {
            for (WriteCommands writeCommand : WriteCommands.values()) {
                if (command.equalsIgnoreCase(writeCommand.name()))
                    return true;
            }
        }

        return false;
    }

    /*----- This methods are used to pre-install and check the accesses of the users in the system. And its not used in the project at runtime -----*/

    protected static void addPermission(String username, String permission) {
        try {
            byte[] keyBytes = LOCAL_ENCRYPTION_KEY.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            String permissionLine = username + ":" + permission + "\n";
            byte[] encryptedContent = cipher.doFinal(permissionLine.getBytes());

            Files.write(Paths.get(ACCESSES_FILE_PATH), encryptedContent, StandardOpenOption.APPEND);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected static Map<String, String> getUserPermissions() {
        return new HashMap<>(new AccessControl().userPermissions);
    }
}