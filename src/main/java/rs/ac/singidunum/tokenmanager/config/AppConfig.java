package rs.ac.singidunum.tokenmanager.config;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class AppConfig {

    // Properties Config
    private static final String CONFIG_FILE = "token-manager.properties";
    public static final String STORAGE_KEY_PATH = "storage.key.path";
    public static final String SERVER_PORT = "server.port";

    // Properties inital Values
    private static final String STORAGE_KEY_PATH_VALUE = "tokens";
    private static final int SERVER_PORT_VALUE = 8000;

    // Data
    private final Properties properties = new Properties();
    private static AppConfig instance;

    public static synchronized AppConfig getInstance() {
        if (instance == null) {
            instance = new AppConfig();
        }
        return instance;
    }

    private AppConfig() {
        Path path = Paths.get(CONFIG_FILE);

        if (!Files.exists(path)) {
            createDefaults();
        } else {
            loadDefaults();
        }
    }

    private void loadDefaults() {
        try(InputStream ins = new FileInputStream(Path.of(CONFIG_FILE).toFile())) {
            properties.load(ins);
        } catch (IOException e) {
            System.out.println("Error reading config file");
            throw new RuntimeException(e);
        }
    }

    private void createDefaults() {
        properties.setProperty(STORAGE_KEY_PATH, STORAGE_KEY_PATH_VALUE);
        properties.setProperty(SERVER_PORT, String.valueOf(SERVER_PORT_VALUE));

        saveConfig();
    }

    public String getProperty(String name) {
        return properties.getProperty(name);
    }

    public void setProperty(String name, String value) {
        properties.setProperty(name, value);
    }

    private void saveConfig() {
        try(OutputStream out = new FileOutputStream(Path.of(CONFIG_FILE).toFile())) {
            properties.store(out, "Token manager - Initial Config");
        } catch (IOException e) {
            System.out.println("Error saving config file");
            throw new RuntimeException(e);
        }
    }


}
