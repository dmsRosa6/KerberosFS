package dmsrosa.kerberosfs.handlers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.util.UUID;
import java.util.logging.Level;

import javax.crypto.SecretKey;

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

    /**
     * Sends the service request to the server.
     *
     * @param oos the ObjectOutputStream obtained from the lazy stream helper
     * @param sgt the response from the TGS (contains the service ticket and session key)
     * @param encryptedAuthenticator the encrypted authenticator (typically serialized)
     * @param command the service command to be executed
     */
    public void sendServiceRequest(ObjectOutputStream oos, ResponseTGSMessage sgt, byte[] encryptedAuthenticator, Command command, UUID session) {
        try {
            // Create a RequestServiceMessage that wraps the service ticket, encrypted authenticator, and the command.
            RequestServiceMessage requestServiceMessage = new RequestServiceMessage(sgt.getSgt(), encryptedAuthenticator, command);

            // Serialize the request message.
            byte[] requestMessageSerialized = RandomUtils.serialize(requestServiceMessage);

            // Wrap the serialized message into a Wrapper.
            Wrapper wrapper = new Wrapper((byte) 3, requestMessageSerialized, session);

            // Send the wrapper to the dispatcher.
            oos.writeObject(wrapper);
            oos.flush();
        } catch (IOException e) {
            Client.logger.log(Level.SEVERE, "Error sending service request", e);
        }
    }

    /**
     * Processes the service response from the server.
     *
     * @param ois the ObjectInputStream obtained from the lazy stream helper
     * @param responseTGSMessage the original TGS response (to obtain the client service key)
     * @return the parsed ResponseServiceMessage or null if an error occurs
     */
    public ResponseServiceMessage processServiceResponse(ObjectInputStream ois, ResponseTGSMessage responseTGSMessage) {
        try {
            // Read the wrapper that contains the encrypted response.
            Wrapper wrapper = (Wrapper) ois.readObject();
            byte[] encryptedResponse = wrapper.getMessage();

            // Use the session key from the TGS response to decrypt the server's reply.
            SecretKey clientServiceKey = responseTGSMessage.getSessionKey();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(clientServiceKey, encryptedResponse);

            // Deserialize and return the ResponseServiceMessage.
            return (ResponseServiceMessage) RandomUtils.deserialize(decryptedResponse);
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | CryptoException e) {
            Client.logger.log(Level.WARNING, e.getMessage());
            return null;
        }
    }
}
