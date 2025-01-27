package org.example.drivers;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.example.utils.MessageStatus;
import org.example.utils.Pair;

public class LocalFileSystemDriver {

    public LocalFileSystemDriver() {
    }

    public int uploadFile(byte[] payload, String targetFilePath) {
        try {
            Path path = Paths.get(targetFilePath);
            Files.createDirectories(path.getParent());
            Files.write(path, payload);
        } catch (IOException e) {
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
        return MessageStatus.OK_NO_CONTENT.getCode();
    }

    public int createFolder(String path) {
        Path folderPath = Path.of(path + "/");
        try {
            Files.createDirectories(folderPath);
            return MessageStatus.OK_NO_CONTENT.getCode();
        } catch (FileAlreadyExistsException e) {
            return MessageStatus.CONFLICT.getCode();
        } catch (IOException e) {
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
    }

    public Pair<byte[], Integer> downloadFile(String filePath) {
        try {
            Path sourcePath = Path.of(filePath);
            Pair<byte[], Integer> temp = new Pair<>(Files.readAllBytes(sourcePath), MessageStatus.OK.getCode());
            return temp;
        } catch (NoSuchFileException e) {
            return new Pair<>(null, MessageStatus.NOT_FOUND.getCode());
        } catch (IOException e) {
            return new Pair<>(null, MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }
    }

    public Pair<List<String>, Integer> listFolder(String path) {
        List<String> fileList = new ArrayList<>();
        Path folderPath = Path.of(path);
        try (Stream<Path> paths = Files.list(folderPath)) {
            paths.forEach(p -> {
                String fileName = p.getFileName().toString();
                if (Files.isDirectory(p)) {
                    fileList.add(fileName + " (Directory)");
                } else {
                    fileList.add(fileName);
                }
            });
            return new Pair<>(fileList,
                    fileList.size() > 0 ? MessageStatus.OK.getCode() : MessageStatus.OK_NO_CONTENT.getCode());
        } catch (IOException e) {
            return new Pair<>(null, MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }
    }

    public int copyFile(String fromPath, String toPath) {
        try {
            Path sourcePath = Path.of(fromPath);
            Path targetPath = Path.of(toPath);
            Files.copy(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (NoSuchFileException e) {
            return MessageStatus.NOT_FOUND.getCode();
        } catch (IOException e) {
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
        return MessageStatus.OK_NO_CONTENT.getCode();
    }

    public int deleteFile(String path) {
        try {
            Path filePath = Path.of(path);
            Files.delete(filePath);
        } catch (NoSuchFileException e) {
            return MessageStatus.NOT_FOUND.getCode();
        } catch (IOException e) {
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
        return MessageStatus.OK_NO_CONTENT.getCode();
    }

    public Pair<BasicFileAttributes, Integer> fileMetadata(String path) {
        try {
            Path filePath = Path.of(path);
            BasicFileAttributes attrs = Files.readAttributes(filePath, BasicFileAttributes.class);
            return new Pair<>(attrs, MessageStatus.OK.getCode());
        } catch (NoSuchFileException e) {
            return new Pair<>(null, MessageStatus.NOT_FOUND.getCode());
        } catch (IOException e) {
            return new Pair<>(null, MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }
    }
}
