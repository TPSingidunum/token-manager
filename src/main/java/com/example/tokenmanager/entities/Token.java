package com.example.tokenmanager.entities;

import java.nio.file.Path;

public class Token {
    private final String name;
    private final Path certificatePath;
    private final Path privateKeyPath;

    public Token(String name, Path certificatePath, Path privateKeyPath) {
        this.name = name;
        this.certificatePath = certificatePath;
        this.privateKeyPath = privateKeyPath;
    }

    public String getName() {
        return name;
    }

    public Path getCertificatePath() {
        return certificatePath;
    }

    public Path getPrivateKeyPath() {
        return privateKeyPath;
    }
}
