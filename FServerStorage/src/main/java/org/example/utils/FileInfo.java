package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

public class FileInfo implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final UUID header;
    private final List<UUID> chunks;

    public FileInfo(UUID header, LinkedList<UUID> chunks) {
        this.header = header;
        this.chunks = chunks;
    }

    public UUID getHeader() {
        return header;
    }

    public List<UUID> getChunks() {
        return chunks;
    }

    @Override
    public String toString() {
        return "FileInfo{" +
                "header=" + header +
                ", chunks=" + chunks +
                '}';
    }
}
