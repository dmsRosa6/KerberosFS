package dmsrosa.kerberosfs;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

public class UserFileWriter {

    private static final String FILE_PATH = "users.txt";

    public static void main(String[] args) {
        // Create some example users
        Map<String, User> users = new HashMap<>();
        try {
            users.put("dmsrosa", new User("dmsrosa", "securepass"));
        } catch (Exception e) {
            System.err.println("Error creating users: " + e.getMessage());
            return;
        }

        // Write users to file
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_PATH))) {
            oos.writeObject(users);
            System.out.println("User data successfully written to " + FILE_PATH);
        } catch (IOException e) {
            System.err.println("Error writing user data to file: " + e.getMessage());
        }
    }
}
