package dmsrosa.kerberosfs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class AccessInstaller {

    private static final String LOCAL_ENCRYPTION_KEY = "LwSIXXbm75btRD3zEDPkWFueMZUxnVxO";
    private static final String RESOURCE_FILE_PATH = "access.conf"; // File in resources

    // Add a new user's permission and save to the file
    public static void addPermission(String username, String permission) {
        try {
            ensureResourceFileExists();

            byte[] keyBytes = LOCAL_ENCRYPTION_KEY.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            String permissionLine = username + ":" + permission + "\n";
            byte[] encryptedContent = cipher.doFinal(permissionLine.getBytes());

            Path resourceFilePath = Paths.get(RESOURCE_FILE_PATH);
            Files.write(resourceFilePath, encryptedContent, StandardOpenOption.APPEND);
            System.out.println("Permission added successfully for user: " + username);
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException |
                 IllegalBlockSizeException | NoSuchPaddingException e) {
            System.err.println("Failed to add permission: " + e.getMessage());
        }
    }

    // Initialize the access file with default permissions (overwrites the file)
    public static void initializePermissions(String[] users, String[] permissions) {
        try {
            ensureResourceFileExists();

            if (users.length != permissions.length) {
                throw new IllegalArgumentException("User and permission arrays must have the same length.");
            }

            byte[] keyBytes = LOCAL_ENCRYPTION_KEY.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            StringBuilder content = new StringBuilder();
            for (int i = 0; i < users.length; i++) {
                content.append(users[i]).append(":").append(permissions[i]).append("\n");
            }

            byte[] encryptedContent = cipher.doFinal(content.toString().getBytes());
            Path resourceFilePath = Paths.get(RESOURCE_FILE_PATH);
            Files.write(resourceFilePath, encryptedContent);
            System.out.println("Access file initialized successfully.");
        } catch (Exception e) {
            System.err.println("Failed to initialize access file: " + e.getMessage());
        }
    }

    // Ensure the resource file exists, if not create it
    private static void ensureResourceFileExists() throws IOException {
        Path resourcePath = Paths.get(RESOURCE_FILE_PATH);

        // Check if the resource file exists in the resources directory
        if (!Files.exists(resourcePath)) {
            // If the file does not exist, create a new empty file
            Files.createFile(resourcePath);
            System.out.println("Resource file created: " + RESOURCE_FILE_PATH);
        } else {
            System.out.println("Resource file already exists: " + RESOURCE_FILE_PATH);
        }
    }

    public static void main(String[] args) {
        // Example initialization of permissions for users
        initializePermissions(new String[]{"dmsrosa"}, new String[]{"rw"});
    }
}
