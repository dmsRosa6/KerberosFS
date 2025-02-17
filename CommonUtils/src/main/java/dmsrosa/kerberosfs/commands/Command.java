package dmsrosa.kerberosfs.commands;

import java.io.Serial;

import dmsrosa.kerberosfs.messages.FilePayload;

public class Command implements java.io.Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String username;
    private final FilePayload file;
    private String path;
    private String cpToPath;
    private CommandTypes type;

    public Command(String username, FilePayload file, String path, CommandTypes type) {
        this.username = username;
        this.file = file;
        this.path = path;
        this.cpToPath = null;
        this.type = type;
    }

    public Command(String username, FilePayload file, String path, String cpToPath, CommandTypes type) {
        this.username = username;
        this.file = file;
        this.path = path;
        this.cpToPath = cpToPath;
        this.type = type;
    }

    public Command(String username, String path, CommandTypes type) {
        this.username = username;
        this.file = null;
        this.path = path;
        this.cpToPath = null;
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public String getCpToPath() {
        return cpToPath;
    }

    public CommandTypes getCommand() {
        return type;
    }

    public FilePayload getPayload() {
        return file;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String s){
        this.path = s;
    }

    public void setCpToPath(String s){
        this.cpToPath = s;
    }
    
    @Override
    public String toString() {
        return "Command{" +
                "command='" + type.toString() + '\'' +
                ", username='" + username + '\'' +
                ", path='" + path + '\'' +
                ", cpToPath='" + (cpToPath == null ? "null" : cpToPath) + '\'' +
                ", file=" + (file == null ? "null" : file) +
                '}';
    }
}
