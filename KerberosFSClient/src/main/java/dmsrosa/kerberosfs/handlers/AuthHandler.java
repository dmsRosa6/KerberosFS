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
import dmsrosa.kerberosfs.messages.RequestAuthenticationMessage;
import dmsrosa.kerberosfs.messages.ResponseAuthenticationMessage;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class AuthHandler {

    /**
     * Sends the authentication request using the provided ObjectOutputStream.
     *
     * @param oos      the ObjectOutputStream (lazily created) to use for sending the request
     * @param clientId the client identifier (username)
     */
    public void sendAuthRequest(ObjectOutputStream oos, String clientId, UUID session) {
        try {
            Client.logger.info("Sending auth request for client: " + clientId);
            RequestAuthenticationMessage requestMessage = new RequestAuthenticationMessage(
                    clientId,
                    Client.CLIENT_ADDR,
                    Client.TGS_ID
            );
            byte[] serializedRequest = RandomUtils.serialize(requestMessage);
            byte[] encryptedRequestMessage = CryptoStuff.getInstance().encrypt(
                    Client.usersInfo.get(clientId).getDhKey(),
                    serializedRequest
            );

            // Create a wrapper with the encrypted request message
            Wrapper wrapper = new Wrapper((byte) 1, encryptedRequestMessage, session);
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException | InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.warning("Error on auth: " + e.getMessage());
        }
    }

    /**
     * Processes the authentication response using the provided ObjectInputStream.
     *
     * @param ois      the ObjectInputStream (lazily created) to use for reading the response
     * @param clientId the client identifier (username)
     * @param password the password provided by the user (used for error handling in this example)
     * @return a ResponseAuthenticationMessage containing the authentication data, or null if an error occurs
     * @throws Exception if a fatal error occurs during processing
     */
    public ResponseAuthenticationMessage processAuthResponse(ObjectInputStream ois, String clientId, String password) throws Exception {
        Client.logger.log(Level.INFO, "Processing auth response for client: " + clientId);
        ResponseAuthenticationMessage responseAuthenticationMessage = null;
        try {
            Wrapper wrapper = (Wrapper) ois.readObject();
            MessageStatus responseStatus = MessageStatus.fromCode(wrapper.getStatus());
            switch (responseStatus) {
                case OK:
                    byte[] encryptedResponse = wrapper.getMessage();
                    try {
                        SecretKey clientKey = Client.usersInfo.get(clientId).getKeyPassword();
                        byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(clientKey, encryptedResponse);
                        responseAuthenticationMessage = (ResponseAuthenticationMessage) RandomUtils.deserialize(decryptedResponse);
                    } catch (CryptoException e) {
                        throw new RuntimeException("This password is incorrect.");
                    }
                    break;
                case UNAUTHORIZED:
                    throw new RuntimeException("Wrong username or password.");
                default:
                    throw new RuntimeException("Unexpected response status: " + responseStatus);
            }
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }
        return responseAuthenticationMessage;
    }
}
