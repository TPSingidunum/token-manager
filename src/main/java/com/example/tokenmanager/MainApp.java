package com.example.tokenmanager;

import com.dustinredmond.fxtrayicon.FXTrayIcon;
import com.example.tokenmanager.configs.AppConfig;
import com.example.tokenmanager.configs.CorsFilter;
import com.example.tokenmanager.configs.TokenManager;
import com.example.tokenmanager.entities.Token;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.MenuItem;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Executors;

public class MainApp extends Application {
    private Stage primaryStage;
    private FXTrayIcon systemTray;
    private TokenManager tokenManager = new TokenManager();
    private final AppConfig appConfig = AppConfig.getInstance();

    @Override
    public void start(Stage stage) throws IOException {
        this.primaryStage = stage;
        appConfig.addProperty("url.stylesheet", String.valueOf(MainApp.class.getResource("style.css")));
        appConfig.addProperty("url.image", String.valueOf(MainApp.class.getResource("tray.png")));

        FXMLLoader fxmlLoader = new FXMLLoader(MainApp.class.getResource("main-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load());
        scene.getStylesheets().add(appConfig.getProperty("url.stylesheet"));

        primaryStage.setTitle("Token Manager");
        primaryStage.setScene(scene);
        primaryStage.setOnCloseRequest(this::hidePrimaryStage);
        primaryStage.show();

        Platform.runLater(this::systemTray);
        startHttpsServer();
    }

    public static void main(String[] args) {
        launch();
    }

    public void hidePrimaryStage(WindowEvent event) {
        event.consume();
        primaryStage.hide();
    }

    //TODO: System tray problem with java17
    private void systemTray() {
        systemTray = new FXTrayIcon(primaryStage, new Image(appConfig.getProperty("url.image")));
        systemTray.setApplicationTitle("Token Manager");

        MenuItem open = new MenuItem("Open");
        open.setOnAction(e -> {
            // Otvori glavni prozor
            primaryStage.show();
            primaryStage.toFront();
        });

        MenuItem close = new MenuItem("Close");
        open.setOnAction(e -> {
            // Otvori glavni prozor
            systemTray.hide();
            Platform.exit();
        });

        systemTray.addMenuItem(open);
        systemTray.addSeparator();
        systemTray.addMenuItem(close);
        systemTray.show();
    }

    private void startHttpsServer() {
        try {
            HttpsServer https = HttpsServer.create(new InetSocketAddress(8433), 0);
            Path certPath = Path.of(appConfig.getCertificatePath());
            Path privPath = Path.of(appConfig.getPrivateKeyPath());
            SSLContext sslContext = createSLLContext(certPath, privPath);
            https.setHttpsConfigurator(new HttpsConfigurator(sslContext));

            // Endpoint
            HttpContext statusContext = https.createContext("/api/status", this::handleStatus);
            HttpContext tokenContext = https.createContext("/api/tokens", this::handleTokens);
//            HttpContext publicKeyContext = https.createContext("/api/public-key", this::handlePublicKey);
//            HttpContext fileContext =  https.createContext("/api/decrypt/file", this::handleDecrypt);

            // Podesio cors
            statusContext.getFilters().add(new CorsFilter());
            tokenContext.getFilters().add(new CorsFilter());
//            publicKeyContext.getFilters().add(new CorsFilter());
//            fileContext.getFilters().add(new CorsFilter());

            https.setExecutor(Executors.newFixedThreadPool(2));
            https.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void handleTokens(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        List<Token> tokens = tokenManager.getTokens();
        StringBuilder result = new StringBuilder("[");

        for (int i = 0; i < tokens.size(); i++) {
            result.append("\"").append(tokens.get(i).getName()).append("\"");

            if ( i != (tokens.size() - 1)) {
               result.append(",");
            }
        }
        result.append("]");
        byte[] data = result.toString().getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, data.length);
        exchange.getResponseBody().write(data);
        exchange.close();
    }

    private void handleStatus(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        String json = "{\"status\":\"active\"}";
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, data.length);
        exchange.getResponseBody().write(data);
        exchange.close();
    }

    private SSLContext createSLLContext(Path certPath, Path privPath) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            PEMParser certReader = new PEMParser(new FileReader(certPath.toFile()));
            X509CertificateHolder certHolder = (X509CertificateHolder) certReader.readObject();
            certReader.close();
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

            PEMParser privReader = new PEMParser(new FileReader(privPath.toFile()));
            PEMKeyPair pemKeyPair = (PEMKeyPair) privReader.readObject();
            privReader.close();
            PrivateKey key = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null);
            keyStore.setKeyEntry("alias", key, new char[0], new Certificate[]{cert});

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, new char[0]);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(keyManagerFactory.getKeyManagers(), null, null);

            return ctx;

        } catch (IOException | CertificateException | KeyStoreException | KeyManagementException |
                 NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String replaceLast(String text, String regex, String replacement) {
        int index = text.lastIndexOf(regex);
        if (index == -1) {
            return text;
        }
        return text.substring(0, index) + replacement + text.substring(index + regex.length());
    }
}