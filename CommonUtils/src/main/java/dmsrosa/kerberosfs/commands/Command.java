package dmsrosa.kerberosfs.commands;

import java.io.Serial;

import dmsrosa.kerberosfs.messages.FilePayload;

public class Command implements java.io.Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String command;
    private final String username;
    private final FilePayload file;
    private final String path;
    private final String cpToPath;

    public Command(String command, String username, FilePayload file, String path) {
        this.command = command;
        this.username = username;
        this.file = file;
        this.path = path;
        this.cpToPath = null;
    }

    public Command(String command, String username, FilePayload file, String path, String cpToPath) {
        this.command = command;
        this.username = username;
        this.file = file;
        this.path = path;
        this.cpToPath = cpToPath;
    }

    public Command(String command, String username, String path) {
        this.command = command;
        this.username = username;
        this.file = null;
        this.path = path;
        this.cpToPath = null;
    }

    public String getUsername() {
        return username;
    }

    public String getCpToPath() {
        return cpToPath;
    }

    public String getCommand() {
        return command;
    }

    public FilePayload getPayload() {
        return file;
    }

    public String getPath() {
        return path;
    }

    public boolean isValid() {
        return !(path.contains("../") || (cpToPath != null && cpToPath.contains("../")));
    }

    @Override
    public String toString() {
        return "Command{" +
                "command='" + command + '\'' +
                ", username='" + username + '\'' +
                ", path='" + path + '\'' +
                ", cpToPath='" + (cpToPath == null ? "null" : cpToPath) + '\'' +
                ", file=" + (file == null ? "null" : file) +
                '}';
    }
}
