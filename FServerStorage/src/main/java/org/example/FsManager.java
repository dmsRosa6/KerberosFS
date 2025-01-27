package org.example;

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
 * FsManager is a class that manages the file system and the Dropbox driver.
 */
public 
class FsManager {
    private static final Logger LOGGER = Logger.getLogger(FsManager.class.getName());
    private final Path rootPath;

    public FsManager(String rootPath) throws IOException {
        this.rootPath = Paths.get(rootPath);
        if (!Files.exists(this.rootPath)) {
            Files.createDirectories(this.rootPath);
        }
    }

    public List<String> listFolder(String folderPath) throws IOException {
        Path folder = rootPath.resolve(folderPath).normalize();
        validatePath(folder);

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder)) {
            List<String> fileList = new ArrayList<>();
            for (Path entry : stream) {
                fileList.add(entry.getFileName().toString());
            }
            return fileList;
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error listing folder contents", e);
            throw e;
        }
    }

    public void writeFile(String filePath, String content) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        validatePath(file);

        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error writing file", e);
            throw e;
        }
    }

    public String readFile(String filePath) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        validatePath(file);

        if (!Files.exists(file)) {
            throw new FileNotFoundException("File not found: " + filePath);
        }

        try {
            return Files.readString(file);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error reading file", e);
            throw e;
        }
    }

    public void deleteFile(String filePath) throws IOException {
        Path file = rootPath.resolve(filePath).normalize();
        validatePath(file);

        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error deleting file", e);
            throw e;
        }
    }

    private void validatePath(Path path) throws IOException {
        if (!path.startsWith(rootPath)) {
            throw new SecurityException("Invalid file path: " + path);
        }
    }
}