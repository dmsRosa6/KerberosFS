package dmsrosa.kerberosfs.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoStuff {

    private static CryptoStuff instance;

    // Recommended IV size for GCM is 12 bytes.
    private static final int IV_SIZE = 12;
    // Authentication tag length in bits.
    private static final int TAG_LENGTH_BIT = 128;

    private CryptoStuff() {
        // No fixed IV here
    }

    public static CryptoStuff getInstance() {
        if (instance == null) {
            instance = new CryptoStuff();
        }
        return instance;
    }

    /**
     * Encrypts the inputBytes using AES/GCM/NoPadding.
     * A new random IV is generated for each encryption and is prepended
     * to the ciphertext.
     *
     * @param key the SecretKey to use for encryption
     * @param inputBytes the plaintext bytes
     * @return a byte array consisting of [IV || ciphertext]
     * @throws CryptoException if encryption fails
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid
     */
    public byte[] encrypt(Key key, byte[] inputBytes) throws CryptoException, InvalidAlgorithmParameterException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            // Generate a new random IV for this encryption operation.
            byte[] iv = new byte[IV_SIZE];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            byte[] cipherText = cipher.doFinal(inputBytes);

            // Prepend IV to ciphertext so that it can be used during decryption.
            byte[] cipherTextWithIv = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
            System.arraycopy(cipherText, 0, cipherTextWithIv, iv.length, cipherText.length);

            return cipherTextWithIv;
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException 
                | NoSuchPaddingException | InvalidKeyException ex) {
            throw new CryptoException("Error encrypting data: " + ex.getMessage());
        }
    }

    /**
     * Decrypts the inputBytes (which should be of the form [IV || ciphertext])
     * using AES/GCM/NoPadding.
     *
     * @param key the SecretKey to use for decryption
     * @param inputBytes the ciphertext bytes (with IV prepended)
     * @return the decrypted plaintext bytes
     * @throws CryptoException if decryption fails (e.g. due to tag mismatch)
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid
     */
    public byte[] decrypt(Key key, byte[] inputBytes) throws CryptoException, InvalidAlgorithmParameterException {
        try {
            if (inputBytes.length < IV_SIZE) {
                throw new CryptoException("Input data is too short to contain IV.");
            }
            // Extract IV from the beginning of the input.
            byte[] iv = new byte[IV_SIZE];
            System.arraycopy(inputBytes, 0, iv, 0, IV_SIZE);

            // The remainder is the actual ciphertext.
            byte[] cipherText = new byte[inputBytes.length - IV_SIZE];
            System.arraycopy(inputBytes, IV_SIZE, cipherText, 0, cipherText.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            return cipher.doFinal(cipherText);
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException 
                | NoSuchPaddingException | InvalidKeyException ex) {
            throw new CryptoException("Error decrypting data: " + ex.getMessage());
        }
    }

    public SecretKey convertStringToSecretKey(String encodedKey) {
        byte[] decodedKey = hexToBytes(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }

    public SecretKey convertByteArrayToSecretKey(byte[] key) {
        SecretKey secretKey = new SecretKeySpec(key, 0, key.length, "AES");
        return secretKey;
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] ans = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            ans[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return ans;
    }
}
