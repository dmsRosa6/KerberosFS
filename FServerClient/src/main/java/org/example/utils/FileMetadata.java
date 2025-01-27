package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

public class FileMetadata implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final long size;
    private final SerializableFileTime creationTime;
    private final SerializableFileTime lastAccessTime;
    private final SerializableFileTime lastModifiedTime;
    private final boolean isDirectory;
    private final boolean isRegularFile;
    private final boolean isSymbolicLink;
    private final boolean isOther;

    public FileMetadata(BasicFileAttributes attrs) {
        this.size = attrs.size();
        this.creationTime = new SerializableFileTime(attrs.creationTime());
        this.lastAccessTime = new SerializableFileTime(attrs.lastAccessTime());
        this.lastModifiedTime = new SerializableFileTime(attrs.lastModifiedTime());
        this.isDirectory = attrs.isDirectory();
        this.isRegularFile = attrs.isRegularFile();
        this.isSymbolicLink = attrs.isSymbolicLink();
        this.isOther = attrs.isOther();
    }

    public long getSize() {
        return size;
    }

    public FileTime getCreationTime() {
        return creationTime.toFileTime();
    }

    public FileTime getLastAccessTime() {
        return lastAccessTime.toFileTime();
    }

    public FileTime getLastModifiedTime() {
        return lastModifiedTime.toFileTime();
    }

    public boolean isDirectory() {
        return isDirectory;
    }

    public boolean isRegularFile() {
        return isRegularFile;
    }

    public boolean isSymbolicLink() {
        return isSymbolicLink;
    }

    public boolean isOther() {
        return isOther;
    }

    @Override
    public String toString() {
        return "FileMetaData{" +
                "size=" + size +
                ", creationTime=" + creationTime +
                ", lastAccessTime=" + lastAccessTime +
                ", lastModifiedTime=" + lastModifiedTime +
                ", isDirectory=" + isDirectory +
                ", isRegularFile=" + isRegularFile +
                ", isSymbolicLink=" + isSymbolicLink +
                ", isOther=" + isOther +
                '}';
    }

}