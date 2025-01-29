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
import dmsrosa.kerberosfs.commands.Command;
import dmsrosa.kerberosfs.crypto.CryptoException;
import dmsrosa.kerberosfs.crypto.CryptoStuff;
import dmsrosa.kerberosfs.messages.RequestServiceMessage;
import dmsrosa.kerberosfs.messages.ResponseServiceMessage;
import dmsrosa.kerberosfs.messages.ResponseTGSMessage;
import dmsrosa.kerberosfs.messages.Wrapper;
import dmsrosa.kerberosfs.utils.RandomUtils;

public class ServiceHandler {

    // Send the service request to the server
    public void sendServiceRequest(SSLSocket socket, ResponseTGSMessage sgt, byte[] encryptedAuthenticator, Command command) {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestServiceMessage requestServiceMessage = new RequestServiceMessage(sgt.getSgt(),encryptedAuthenticator,command);
            
            byte[] requestMessageSerialized = RandomUtils.serialize(requestServiceMessage);

            // Wrap the serialized message and create a wrapper object for sending
            Wrapper wrapper = new Wrapper((byte) 6, requestMessageSerialized, UUID.randomUUID());

            // Send the wrapper to the dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException  e) {
            Client.logger.log(Level.SEVERE, "Error sending service request", e);
        }
    }

    // Process the response from the service
    public ResponseServiceMessage processServiceResponse(SSLSocket socket,
        ResponseTGSMessage responseTGSMessage) {
        ResponseServiceMessage responseServiceMessage = null;
        try {
            ObjectInputStream ois = null;
            if (!socket.isClosed() && socket.isConnected()) {
                ois = new ObjectInputStream(socket.getInputStream());
            }else{
                Client.logger.warning("bagulho");
            }
            Wrapper wrapper = (Wrapper) ois.readObject();
            byte[] encryptedResponse = wrapper.getMessage();

            SecretKey clientServiceKey = responseTGSMessage.getSessionKey();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(clientServiceKey, encryptedResponse);

            responseServiceMessage = (ResponseServiceMessage) RandomUtils.deserialize(decryptedResponse);
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
        }
        return responseServiceMessage;
    }


}
