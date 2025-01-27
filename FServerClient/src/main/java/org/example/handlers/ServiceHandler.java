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
import org.example.utils.Authenticator;
import org.example.utils.Command;
import org.example.utils.RequestServiceMessage;
import org.example.utils.ResponseServiceMessage;
import org.example.utils.ResponseTGSMessage;
import org.example.utils.Utils;
import org.example.utils.Wrapper;

public class ServiceHandler {

    // Send the service request to the server
    public void sendServiceRequest(SSLSocket socket, Command command, ResponseTGSMessage sgt) {
        try {
            Client.logger.log(Level.SEVERE,"Sending Storage request command: {0} for client: {1} to service: " + Client.SERVICE_ID, new Object[]{command.getCommand(), command.getUsername()});

            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            // Create authenticator object for the client
            Authenticator authenticator = new Authenticator(command.getUsername(), Client.CLIENT_ADDR);
            byte[] encryptedAuthenticator = CryptoStuff.getInstance().encrypt(
                    sgt.getSessionKey(),
                    Utils.serialize(authenticator)
            );

            // Create RequestServiceMessage containing the SGT, encrypted authenticator, and command
            RequestServiceMessage requestServiceMessage = new RequestServiceMessage(sgt.getSgt(),
                    encryptedAuthenticator, command);
            byte[] requestMessageSerialized = Utils.serialize(requestServiceMessage);

            // Wrap the serialized message and create a wrapper object for sending
            Wrapper wrapper = new Wrapper((byte) 6, requestMessageSerialized, UUID.randomUUID());

            // Send the wrapper to the dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException | InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.log(Level.SEVERE, "Error sending service request", e);
        }
    }

    // Process the response from the service
    public ResponseServiceMessage processServiceResponse(SSLSocket socket,
        ResponseTGSMessage responseTGSMessage) {
        Client.logger.severe("Processing Storage response");
        ResponseServiceMessage responseServiceMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();
            byte[] encryptedResponse = wrapper.getMessage();

            SecretKey clientServiceKey = responseTGSMessage.getSessionKey();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(clientServiceKey, encryptedResponse);

            responseServiceMessage = (ResponseServiceMessage) Utils.deserialize(decryptedResponse);
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }
        return responseServiceMessage;
    }


}
