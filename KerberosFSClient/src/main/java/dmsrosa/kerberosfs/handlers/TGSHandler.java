package dmsrosa.kerberosfs.handlers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.util.UUID;
import java.util.logging.Level;

import javax.crypto.SecretKey;

import dmsrosa.kerberosfs.Client;
import dmsrosa.kerberosfs.crypto.CryptoException;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.MessageStatus;
import dmsrosa.kerberosfs.messages.RequestTGSMessage;
import dmsrosa.kerberosfs.messages.ResponseTGSMessage;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class TGSHandler {

    /**
     * Sends a TGS request using the given ObjectOutputStream.
     *
     * @param oos            the ObjectOutputStream (lazily created) to send the request
     * @param encryptedTGT   the encrypted Ticket Granting Ticket
     * @param authenticator  the authenticator data (typically already encrypted)
     */
    public void sendTGSRequest(ObjectOutputStream oos, byte[] encryptedTGT, byte[] authenticator, UUID session) {
        try {
            RequestTGSMessage requestMessage = new RequestTGSMessage(Client.SERVICE_ID, encryptedTGT, authenticator);
            byte[] requestMessageSerialized = RandomUtils.serialize(requestMessage);
            // Create a wrapper object with the serialized request message.
            Wrapper wrapper = new Wrapper((byte) 2, requestMessageSerialized, session);
            // Send the wrapper to the dispatcher.
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }
    }

    /**
     * Processes the TGS response using the given ObjectInputStream and decryption key.
     *
     * @param ois the ObjectInputStream (lazily created) from which to read the response
     * @param key the SecretKey to decrypt the response message
     * @return a ResponseTGSMessage object containing the response data
     * @throws Exception if any error occurs during processing
     */
    public ResponseTGSMessage processTGSResponse(ObjectInputStream ois, SecretKey key) throws Exception {
        ResponseTGSMessage responseTGSMessage = null;
        Wrapper wrapper = null;
        try {
            wrapper = (Wrapper) ois.readObject();
        } catch (ClassNotFoundException | IOException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }
        if (wrapper.getStatus() == MessageStatus.FORBIDDEN.getCode()) {
            throw new RuntimeException("User is trying access a not path that is forbidden");
        } else if (wrapper.getStatus() == MessageStatus.UNAUTHORIZED.getCode()) {
            throw new RuntimeException("User does not have permission to perform that operation");
        }
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
