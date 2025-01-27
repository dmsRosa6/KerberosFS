package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.nio.file.attribute.FileTime;

public class SerializableFileTime implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final long seconds;
    private final int nanos;

    public SerializableFileTime(FileTime fileTime) {
        this.seconds = fileTime.toInstant().getEpochSecond();
        this.nanos = fileTime.toInstant().getNano();
    }

    public FileTime toFileTime() {
        return FileTime.from(java.time.Instant.ofEpochSecond(seconds, nanos));
    }

    @Override
    public String toString() {
        return "FileTime{" +
                "seconds=" + seconds +
                ", nanos=" + nanos +
                '}';
    }
}