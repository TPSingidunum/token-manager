package com.example.tokenmanager.configs;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class AppConfig {
    private static final String CONFIG_FILE = "token-manager.properties";
    private static AppConfig instance;
    private final Properties properties;

    // Default config values
    private static final String DEFAULT_CERT_PATH = "certs/certificate.pem";
    private static final String DEFAULT_PRIVATE_KEY_PATH = "certs/private.pem";
    private static final String DEFAULT_STORAGE_PATH = "tokens";
    private static final String DEFAULT_BACKEND_URL = "http://localhost:8080";
    private static final int DEFAULT_GCM_TAG = 128;

    private AppConfig() {
        properties = new Properties();
        File configFile = new File(CONFIG_FILE);

        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                properties.load(fis);
            } catch (IOException e) {
                System.err.println("Error loading config file: " + e.getMessage());
                setDefaults();
            }
        } else {
            setDefaults();
            saveConfig();
        }
    }

    private void setDefaults() {
        properties.setProperty("path.certificate", DEFAULT_CERT_PATH);
        properties.setProperty("path.private-key", DEFAULT_PRIVATE_KEY_PATH);
        properties.setProperty("path.storage", DEFAULT_STORAGE_PATH);
        properties.setProperty("backend.url", DEFAULT_BACKEND_URL);
        properties.setProperty("encryption.gcm-tag-size", String.valueOf(DEFAULT_GCM_TAG));

        try {
            Files.createDirectories(Path.of(DEFAULT_CERT_PATH).getParent());
            Files.createDirectories(Path.of(DEFAULT_STORAGE_PATH));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static synchronized AppConfig getInstance() {
        if (instance == null) {
            instance = new AppConfig();
        }
        return instance;
    }

    public String getCertificatePath() {
        return properties.getProperty("path.certificate", DEFAULT_CERT_PATH);
    }

    public String getPrivateKeyPath() {
        return properties.getProperty("path.private-key", DEFAULT_CERT_PATH);
    }

    public Path getTokensStoragePath() {
        return Path.of(properties.getProperty("path.storage", DEFAULT_CERT_PATH));
    }

    public void addProperty(String key, String value) {
        properties.setProperty(key, value);
    }

    public String getProperty(String key) {
        return (String) properties.getOrDefault(key, null);
    }

    public void saveConfig() {
        try {
            File configFile = new File(CONFIG_FILE);
            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                properties.store(fos, "Token Manager Configuration");
            }
        } catch (IOException e) {
            System.err.println("Error saving config file: " + e.getMessage());
        }
    }
}