package dmsrosa.kerberosfs.handlers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.util.UUID;
import java.util.logging.Level;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;

import dmsrosa.kerberosfs.Client;
import dmsrosa.kerberosfs.crypto.CryptoException;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.MessageStatus;
import dmsrosa.kerberosfs.messages.RequestTGSMessage;
import dmsrosa.kerberosfs.messages.ResponseTGSMessage;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class TGSHandler {

        public void sendTGSRequest(SSLSocket socket, byte[] encryptedTGT, byte[] authenticator) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestTGSMessage requestMessage = new RequestTGSMessage(Client.SERVICE_ID, encryptedTGT, authenticator);

            byte[] requestMessageSerialized = RandomUtils.serialize(requestMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 3, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }
    }

    public ResponseTGSMessage processTGSResponse(SSLSocket socket, SecretKey key) throws Exception {
        ResponseTGSMessage responseTGSMessage = null;

        // Communication logic with the server
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(socket.getInputStream());
        } catch (IOException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }

        Wrapper wrapper = null;
        try {
            wrapper = (Wrapper) ois.readObject();
        } catch (ClassNotFoundException | IOException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }
        if (wrapper.getStatus() == MessageStatus.FORBIDDEN.getCode()) {
            throw new RuntimeException("User is trying to use ../ on a absolute path");
        } else if (wrapper.getStatus() == MessageStatus.UNAUTHORIZED.getCode()) {
            throw new RuntimeException("User does not have permission to do that operation");
        }
        // int responseStatus = wrapper.getStatus();
        byte[] encryptedResponse = wrapper.getMessage();
        byte[] decryptedResponse = null;
        try {
            decryptedResponse = CryptoStuff.getInstance().decrypt(key, encryptedResponse);
        } catch (InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }

        try {
            responseTGSMessage = (ResponseTGSMessage) RandomUtils.deserialize(decryptedResponse);
        } catch (ClassNotFoundException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }

        return responseTGSMessage;
    }
}
