package rs.ac.singidunum.tokenmanager.entities;

import java.nio.file.Path;

public class Token {
    public enum TOKEN_TYPE {LOCAL, DEVICE}
    private String keyId;
    private String name;
    private TOKEN_TYPE type;
    private Path certificatePath;
    private Path keyPath;

    // TODO: Token Flags fields, Activated/Installed

    public Token(String keyId, String name, TOKEN_TYPE type, Path certificatePath, Path keyPath) {
        this.keyId = keyId;
        this.name = name;
        this.type = type;
        this.certificatePath = certificatePath;
        this.keyPath = keyPath;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public TOKEN_TYPE getType() {
        return type;
    }

    public void setType(TOKEN_TYPE type) {
        this.type = type;
    }

    public Path getCertificatePath() {
        return certificatePath;
    }

    public void setCertificatePath(Path certificatePath) {
        this.certificatePath = certificatePath;
    }

    public Path getKeyPath() {
        return keyPath;
    }

    public void setKeyPath(Path keyPath) {
        this.keyPath = keyPath;
    }

    @Override
    public String toString() {
        return "Token{" +
                "keyId='" + keyId + '\'' +
                ", name='" + name + '\'' +
                ", type=" + type +
                ", certificatePath=" + certificatePath +
                ", keyPath=" + keyPath +
                '}';
    }
}
