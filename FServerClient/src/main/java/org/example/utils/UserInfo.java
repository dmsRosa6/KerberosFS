package org.example.utils;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.example.crypto.CryptoStuff;

public class UserInfo {

    private ResponseAuthenticationMessage tgt;
    private Map<String, ResponseTGSMessage> mapSGT;
    private SecretKey dhKey;
    private SecretKey keyPassword;

    private static final byte[] salt = {
            0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01, 0x00, 0x0f, 0x0d,
            0x0e, 0x0c, 0x07, 0x06, 0x05, 0x04
    };
    private static final String HASHING_ALGORITHMS = "PBKDF2WithHmacSHA256";

    public UserInfo() {
        mapSGT = new HashMap<>();
        tgt = null;
        dhKey = null;
        keyPassword = null;
    }

    public ResponseAuthenticationMessage getTGT() {
        return tgt;
    }

    public void setTGT(ResponseAuthenticationMessage tgt) {
        this.tgt = tgt;
    }

    public ResponseTGSMessage getSGT(String command) {
        return mapSGT.get(command);
    }

    public void addSGT(String command, ResponseTGSMessage sgt) {
        mapSGT.put(command, sgt);
    }

    public SecretKey getDhKey() {
        return dhKey;
    }

    public void setDhKey(SecretKey dhKey) {
        this.dhKey = dhKey;
    }

    public SecretKey getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        try {
            this.keyPassword = CryptoStuff.getInstance().convertByteArrayToSecretKey(hashPassword(keyPassword));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static byte[] hashPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 10000;
        int keyLength = 256;

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASHING_ALGORITHMS);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return hash;
    }

}
