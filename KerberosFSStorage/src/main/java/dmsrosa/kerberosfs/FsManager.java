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

import dmsrosa.kerberosfs.messages.FilePayload;

public class FsManager {
    private final Path rootPath;

    /**
     * Constructs an FsManager using the given root directory. If the directory does not exist,
     * it will be created.
     *
     * @param rootPath the root directory for file operations.
     * @throws IOException if an I/O error occurs during directory creation.
     */
    public FsManager(String rootPath) throws IOException {
        // Convert to absolute and normalized path.
        this.rootPath = Paths.get(rootPath).toAbsolutePath().normalize();
        if (!Files.exists(this.rootPath)) {
            Files.createDirectories(this.rootPath);
            StorageService.logger.info("Created root directory: " + this.rootPath);
        } else {
            StorageService.logger.info("Using existing root directory: " + this.rootPath);
        }
    }

    /**
     * Ensures that a directory exists for the given user.
     * If it does not exist, it will be created.
     *
     * @param username the name of the user.
     * @return the Path representing the user's directory.
     * @throws IOException if an I/O error occurs.
     */
    public Path ensureUserDirectory(String username) throws IOException {
        Path userDir = rootPath.resolve(username).normalize();
        if (!Files.exists(userDir)) {
            Files.createDirectories(userDir);
            StorageService.logger.info("Created user directory: " + userDir);
        }
        return userDir;
    }

    /**
     * Creates a directory at the specified path if it does not exist.
     *
     * @param dirPath the relative directory path to create.
     * @throws IOException if an I/O error occurs.
     */
    public void mkdir(String dirPath) throws IOException {
        Path dir = rootPath.resolve(dirPath).normalize();
        if (!Files.exists(dir)) {
            Files.createDirectories(dir);
            StorageService.logger.info("Created directory: " + dir);
        } else {
            StorageService.logger.info("Directory already exists: " + dir);
        }
    }

    /**
     * Lists the names of files and directories in the specified folder.
     *
     * @param folderPath the relative folder path to list.
     * @return a list of file/directory names.
     * @throws IOException if the folder does not exist or an I/O error occurs.
     */
    public List<String> listFolder(String folderPath) throws IOException {
        Path folder = rootPath.resolve(folderPath).normalize();
        if (!Files.exists(folder) || !Files.isDirectory(folder)) {
            String msg = "Folder not found or not a directory: " + folder;
            StorageService.logger.warning(msg);
            throw new FileNotFoundException(msg);
        }

        List<String> fileList = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder)) {
            for (Path entry : stream) {
                fileList.add(entry.getFileName().toString());
            }
            StorageService.logger.info("Listed contents of folder " + folder + ": " + fileList);
        } catch (IOException e) {
            String msg = "Error listing folder contents for " + folder;
            StorageService.logger.log(Level.SEVERE, msg, e);
            throw new IOException(msg, e);
        }
        return fileList;
    }

    /**
     * Writes content to the specified file. The parent directories will be created if they do not exist.
     *
     * @param filePath the relative file path to write.
     * @param content  the FilePayload containing the file data.
     * @throws IOException if an I/O error occurs during writing.
     */
    public void writeFile(String filePath, FilePayload content) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        StorageService.logger.info("Writing file: " + file);

        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            byte[] data = content.getFileContent();
            Files.write(file, data, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            StorageService.logger.info("Successfully wrote file: " + file);
        } catch (IOException e) {
            String msg = "Error writing file: " + file;
            StorageService.logger.log(Level.SEVERE, msg, e);
            throw new IOException(msg, e);
        }
    }

    /**
     * Reads the contents of the specified file as a String.
     *
     * @param filePath the relative file path to read.
     * @return the file contents as a String.
     * @throws IOException if the file does not exist or an I/O error occurs.
     */
    public String readFile(String filePath) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        StorageService.logger.info("Reading file: " + file);

        if (!Files.exists(file) || !Files.isRegularFile(file)) {
            String msg = "File not found or not a regular file: " + file;
            StorageService.logger.warning(msg);
            throw new FileNotFoundException(msg);
        }

        try {
            String content = Files.readString(file);
            StorageService.logger.info("Successfully read file: " + file);
            return content;
        } catch (IOException e) {
            String msg = "Error reading file: " + file;
            StorageService.logger.log(Level.SEVERE, msg, e);
            throw new IOException(msg, e);
        }
    }

    /**
     * Deletes the specified file.
     *
     * @param filePath the relative file path to delete.
     * @throws IOException if the file does not exist or an I/O error occurs during deletion.
     */
    public void deleteFile(String filePath) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        StorageService.logger.info("Deleting file: " + file);

        try {
            if (Files.deleteIfExists(file)) {
                StorageService.logger.info("Successfully deleted file: " + file);
            } else {
                String msg = "File not found for deletion: " + file;
                StorageService.logger.warning(msg);
                throw new FileNotFoundException(msg);
            }
        } catch (IOException e) {
            String msg = "Error deleting file: " + file;
            StorageService.logger.log(Level.SEVERE, msg, e);
            throw new IOException(msg, e);
        }
    }
}
