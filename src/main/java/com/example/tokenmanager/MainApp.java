package com.example.tokenmanager;

import com.dustinredmond.fxtrayicon.FXTrayIcon;
import com.example.tokenmanager.configs.AppConfig;
import com.example.tokenmanager.configs.CorsFilter;
import com.example.tokenmanager.configs.TokenManager;
import com.example.tokenmanager.controllers.MainController;
import com.example.tokenmanager.entities.Token;
import com.example.tokenmanager.ui.PinDialog;
import com.sun.net.httpserver.*;
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

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
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

        MainController mainController = fxmlLoader.getController();
        TokenManager tokenManager = new TokenManager();
        mainController.setTokenManager(tokenManager);
        this.tokenManager = tokenManager;

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
            HttpsServer https = HttpsServer.create(new InetSocketAddress(8443), 0);
            Path certPath = Path.of(appConfig.getCertificatePath());
            Path privPath = Path.of(appConfig.getPrivateKeyPath());
            SSLContext sslContext = createSLLContext(certPath, privPath);
            https.setHttpsConfigurator(new HttpsConfigurator(sslContext));

            // Endpoint
            HttpContext statusContext = https.createContext("/api/status", this::handleStatus);
            HttpContext tokenContext = https.createContext("/api/tokens", this::handleTokens);
            HttpContext publicKeyContext = https.createContext("/api/public-key", this::handlePublicKey);
            HttpContext fileContext =  https.createContext("/api/decrypt/file", this::handleDecrypt);

            // Podesio cors
            statusContext.getFilters().add(new CorsFilter());
            tokenContext.getFilters().add(new CorsFilter());
            publicKeyContext.getFilters().add(new CorsFilter());
            fileContext.getFilters().add(new CorsFilter());

            https.setExecutor(Executors.newFixedThreadPool(2));
            https.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void handleDecrypt(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.sendResponseHeaders(405, -1); ex.close(); return;
        }

        // 1) parse out fileId and token name
        String path = ex.getRequestURI().getPath();      // "/api/decrypt/file/123"
        String[] parts = path.split("/");
        int fileId = Integer.parseInt(parts[parts.length - 1]);

        String query = ex.getRequestURI().getQuery();    // "token=MyCert"
        String tokenName;
        if (query != null && query.startsWith("token=")) {
            tokenName = URLDecoder.decode(query.substring(6), StandardCharsets.UTF_8);
        } else {
            tokenName = null;
        }
        if (tokenName == null) {
            ex.sendResponseHeaders(400, -1); ex.close(); return;
        }

        // 2) prompt user for PIN
        String pinStr = PinDialog.requestPin();  // your existing dialog
        if (pinStr == null || pinStr.isEmpty()) {
            ex.sendResponseHeaders(401, -1); ex.close(); return;
        }

        char[] pin = pinStr.toCharArray();

        try {
            // 3) decrypt the on-prem private key
            Token token = tokenManager.getTokens().stream()
                    .filter(t -> t.getName().equals(tokenName))
                    .findFirst()
                    .orElseThrow();
            byte[] pkBytes = tokenManager.decrypt(token, pin);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkBytes);
            PrivateKey privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(spec);

            // 4) fetch the encrypted file + envelope metadata from your storage backend
            String backendUrl = appConfig.getProperty("backend.url");
            System.out.println(backendUrl);
            HttpClient client = HttpClient.newBuilder().build();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(backendUrl + "/api/storage/download/file/" + fileId))
                    .header("Authorization", ex.getRequestHeaders().getFirst("Authorization"))
                    .GET()
                    .build();
            HttpResponse<InputStream> resp = client.send(
                    req,
                    HttpResponse.BodyHandlers.ofInputStream()
            );
            if (resp.statusCode() != 200) {
                ex.sendResponseHeaders(resp.statusCode(), -1);
                ex.close();
                return;
            }

            // 5) pull out X-Envelope-Key & IV
            String envKeyB64 = resp.headers().firstValue("X-Envelope-Key").orElseThrow();
            String ivB64     = resp.headers().firstValue("X-Envelope-IV").orElseThrow();

            byte[] encryptedAesKey = Base64.getDecoder().decode(envKeyB64);
            byte[] ivBytes         = Base64.getDecoder().decode(ivB64);

            // RSA-decrypt the AES key
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] aesKeyBytes = rsa.doFinal(encryptedAesKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // 6) set up GCM decryptor
            int tagBits = Integer.parseInt(appConfig.getProperty("encryption.gcm-tag-size"));
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagBits, ivBytes);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

            // prepare response headers
            Headers rH = ex.getResponseHeaders();
            String cd = resp.headers().firstValue("Content-Disposition").orElse("");
            rH.add("Content-Disposition", cd);
            rH.add("Content-Type", resp.headers().firstValue("Content-Type")
                    .orElse("application/octet-stream"));

            // 7) stream back decrypted payload
            ex.sendResponseHeaders(200, 0);  // chunked
            try (CipherInputStream cis = new CipherInputStream(resp.body(), cipher);
                 OutputStream os       = ex.getResponseBody()) {

                byte[] buf = new byte[8192];
                int len;
                while ((len = cis.read(buf)) != -1) {
                    os.write(buf, 0, len);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            ex.sendResponseHeaders(500, -1);
        } finally {
            ex.close();
        }
    }

    private void handlePublicKey(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String name = "";
        if (query != null && query.startsWith("token=")){
           name = query.substring(6);
        }
        
        Token token = null;
        for (Token t: this.tokenManager.getTokens()) {
            if (t.getName().equalsIgnoreCase(name)) {
                token = t;
            }
        }

        try {
            if (token != null) {
                Path certPath = token.getCertificatePath();
                PEMParser certReader = new PEMParser(new FileReader(certPath.toFile()));
                X509CertificateHolder certHolder = (X509CertificateHolder) certReader.readObject();
                certReader.close();
                X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

                byte[] publicKey = cert.getPublicKey().getEncoded();
                String stringPublicKey = "-----BEGIN PUBLIC KEY-----" + Base64.getEncoder().encodeToString(publicKey) + "-----END PUBLIC KEY-----";

                byte[] data = stringPublicKey.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, data.length);
                exchange.getResponseBody().write(data);
                exchange.close();
            }
        } catch (Exception e) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
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