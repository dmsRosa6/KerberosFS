package dmsrosa.kerberosfs;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * FsManager is a class that manages the file system
 */
public class FsManager {
    private static final Logger LOGGER = Logger.getLogger(FsManager.class.getName());
    private final Path rootPath;

    public FsManager(String rootPath) throws IOException {
        this.rootPath = Paths.get(rootPath);
        if (!Files.exists(this.rootPath)) {
            Files.createDirectories(this.rootPath);
            LOGGER.info("Created root directory");
        } else {
            LOGGER.info("Using existing root directory");
        }
    }

    public List<String> listFolder(String folderPath) throws IOException {
        Path folder = rootPath.resolve(folderPath).normalize();
        validatePath(folder);
        LOGGER.info("Listing contents of folder: " + folder);

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder)) {
            List<String> fileList = new ArrayList<>();
            for (Path entry : stream) {
                fileList.add(entry.getFileName().toString());
            }
            LOGGER.info("Folder contents: " + fileList);
            return fileList;
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error listing folder contents: " + folder);
            throw e;
        }
    }

    public void writeFile(String filePath, String content) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        validatePath(file);
        LOGGER.info("Writing file: " + file);

        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            LOGGER.info("Successfully wrote to file: " + file);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error writing file: " + file, e);
            throw e;
        }
    }

    public String readFile(String filePath) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        validatePath(file);
        LOGGER.info("Reading file: " + file);

        if (!Files.exists(file)) {
            LOGGER.warning("File not found: " + file);
            throw new FileNotFoundException("File not found: " + filePath);
        }

        try {
            String content = Files.readString(file);
            LOGGER.info("Successfully read file: " + file);
            return content;
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error reading file: " + file);
            throw e;
        }
    }

    public void deleteFile(String filePath) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        validatePath(file);
        LOGGER.info("Deleting file: " + file);

        try {
            if (Files.deleteIfExists(file)) {
                LOGGER.info("Successfully deleted file: " + file);
            } else {
                LOGGER.warning("File not found for deletion: " + file);
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error deleting file: " + file);
            throw e;
        }
    }

    private void validatePath(Path path) throws IOException {
        if (!path.startsWith(rootPath)) {
            LOGGER.severe("Security violation: Attempted access outside root directory: " + path);
            throw new SecurityException("Invalid file path: " + path);
        }
    }
}
