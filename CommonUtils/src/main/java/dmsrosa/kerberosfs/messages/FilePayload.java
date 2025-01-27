package dmsrosa.kerberosfs.messages;

import java.io.Serial;
import java.io.Serializable;

public class FilePayload implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final byte[] metaData;
    private final byte[] fileContent;

    public FilePayload(byte[] metaData, byte[] fileContent) {
        this.metaData = metaData;
        this.fileContent = fileContent;
    }

    public byte[] getMetaData() {
        return metaData;
    }

    public byte[] getFileContent() {
        return fileContent;
    }

    @Override
    public String toString() {
        return "FilePayload{" +
                "metaData=" + metaData +
                ", fileContent=" + fileContent +
                '}';
    }
}
