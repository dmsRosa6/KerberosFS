package dmsrosa.kerberosfs.handlers;

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
import org.example.utils.Command;
import org.example.utils.MessageStatus;
import org.example.utils.RequestTGSMessage;
import org.example.utils.ResponseTGSMessage;
import org.example.utils.Utils;
import org.example.utils.Wrapper;

public class TGSHandler {

        public void sendTGSRequest(SSLSocket socket, byte[] encryptedTGT, byte[] encryptedAuthenticator,
            Command command) {
        try {
            Client.logger.log(Level.SEVERE,"Sending TGS request command: {0} for client: {1} to service: " + Client.SERVICE_ID, new Object[]{command.getCommand(), command.getUsername()});
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestTGSMessage requestMessage = new RequestTGSMessage(Client.SERVICE_ID, encryptedTGT, encryptedAuthenticator);

            byte[] requestMessageSerialized = Utils.serialize(requestMessage);

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
        Client.logger.severe("Processing TGS response");
        ResponseTGSMessage responseTGSMessage = null;

        // Communication logic with the server
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(socket.getInputStream());
        } catch (IOException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }

        Client.logger.info("Waiting for TGS response");
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
        Client.logger.info("Attempting to decrypt TGS response");
        // int responseStatus = wrapper.getStatus();
        byte[] encryptedResponse = wrapper.getMessage();
        byte[] decryptedResponse = null;
        try {
            decryptedResponse = CryptoStuff.getInstance().decrypt(key, encryptedResponse);
        } catch (InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }

        Client.logger.info("Attempting to deserialize TGS response");
        try {
            responseTGSMessage = (ResponseTGSMessage) Utils.deserialize(decryptedResponse);
        } catch (ClassNotFoundException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }

        Client.logger.info("Finished processing TGS response");

        return responseTGSMessage;
    }
}
