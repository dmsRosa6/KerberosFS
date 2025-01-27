package org.example.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Utilities
 */
public class Utils
{



    /**
     * Criacao de uma chave AES
     *
     * @param bitLength
     * @param random
     * @return Chave AES
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(
            int          bitLength,
            SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES");

        generator.init(256, random);

        return generator.generateKey();
    }

    /**
     * Criar um IV para usar em AES e modo CTR
     * <p>
     * IV composto por 4 bytes (numero de emensagem)
     * 4 bytes de random e um contador de 8 bytes.
     *
     * @param messageNumber - Numero da mensagem
     * @param random - source ou seed para random
     * @return Vector IvParameterSpec inicializado
     */
    public static IvParameterSpec createCtrIvForAES(
            int             messageNumber,
            SecureRandom    random)
    {
        byte[]          ivBytes = new byte[16];

        // initially randomize

        random.nextBytes(ivBytes);

        // set the message number bytes

        ivBytes[0] = (byte)(messageNumber >> 24);
        ivBytes[1] = (byte)(messageNumber >> 16);
        ivBytes[2] = (byte)(messageNumber >> 8);
        ivBytes[3] = (byte)(messageNumber >> 0);

        // set the counter bytes to 1

        for (int i = 0; i != 7; i++)
        {
            ivBytes[8 + i] = 0;
        }

        ivBytes[15] = 1;

        return new IvParameterSpec(ivBytes);
    }

    /**
     * Converte um byte array de 8 bits numa string
     *
     * @param bytes array contendo os caracteres
     * @param length N. de bytes a processar
     * @return String que representa os bytes
     */
    public static String toString(
            byte[] bytes,
            int    length)
    {
        char[]	chars = new char[length];

        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }

        return new String(chars);
    }

    /**
     * Convete um array de caracteres de 8 bits numa string
     *
     * @param bytes - Array que contem os caracteres
     * @return String com a representacao dos bytes
     */
    public static String toString(
            byte[]	bytes)
    {
        return toString(bytes, bytes.length);
    }

    /**
     * Converte a string passada num array de bytes
     * a partir dos 8 bits de cada caracter contido no array
     *
     * @param string - String a converter
     * @return - retorna representacao em array de bytes
     */
    public static byte[] toByteArray(
            String string)
    {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }

    public static byte[] bytesToHexByteArray(byte[] bytes) {
        byte[] hexArray = new byte[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xFF;
            hexArray[i * 2] = (byte) ((value >> 4) & 0xF);
            hexArray[i * 2 + 1] = (byte) (value & 0xF);
        }
        return hexArray;
    }


    /**
     * Convert a byte array to a hexadecimal string
     * @param data
     * @param length
     * @return
     */
    public static String toHex(byte[] data, int length) {
        StringBuffer	buf = new StringBuffer();
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            String digits = "0123456789abcdef";
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    /**
     *  Convert a byte array to a hexadecimal string
     * @param data
     * @return
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

    /**
     * Convert a string in hexadecimal to a byte array
     * @param s
     * @return
     */
    public static byte[] hexStringToByteArray(String s) {
        if (s == null || s.equalsIgnoreCase("null")) return new byte[] {};

        int len = s.length();

        // Check if the length is odd, and pad with a leading zero if needed
        if (len % 2 != 0) {
            s = "0" + s;
            len++;
        }

        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }

        return data;
    }


}