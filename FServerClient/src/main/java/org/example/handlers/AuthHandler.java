package org.example.handlers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.util.UUID;
import java.util.logging.Level;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;

import org.example.Client;
import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.utils.MessageStatus;
import org.example.utils.RequestAuthenticationMessage;
import org.example.utils.ResponseAuthenticationMessage;
import org.example.utils.Utils;
import org.example.utils.Wrapper;

public class AuthHandler {

    // Process login (send credentials)
    public void sendAuthRequest(SSLSocket socket, String clientId) {
        try {
            Client.logger.severe("Sending auth request for client: " + clientId);

            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestAuthenticationMessage requestMessage = new RequestAuthenticationMessage(clientId, Client.CLIENT_ADDR,
                    Client.TGS_ID);

            byte[] encryptedRequestMessge = CryptoStuff.getInstance().encrypt(Client.usersDHKey.get(clientId).getDhKey(),
                    Utils.serialize(requestMessage));

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 1, encryptedRequestMessge, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException | InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.warning("Error on auth: " + e.getMessage());
        }
    }

    public ResponseAuthenticationMessage processAuthResponse(SSLSocket socket, String clientId,
            String password) throws Exception {
        Client.logger.log(Level.SEVERE, "Processing auth response for client: {0}", clientId);
        ResponseAuthenticationMessage responseAuthenticationMessage = null;
        try {
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();
            MessageStatus responseStatus = MessageStatus.fromCode(wrapper.getStatus());
            switch (responseStatus) {
                case OK:
                    byte[] encryptedResponse = wrapper.getMessage();
                    try {
                        SecretKey clientKey = Client.usersDHKey.get(clientId).getKeyPassword();
                        byte[] descryptedResponse = CryptoStuff.getInstance().decrypt(clientKey, encryptedResponse);
                        responseAuthenticationMessage = (ResponseAuthenticationMessage) Utils.deserialize(descryptedResponse);
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
