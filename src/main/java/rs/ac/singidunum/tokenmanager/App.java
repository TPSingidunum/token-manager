package rs.ac.singidunum.tokenmanager;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.operator.OperatorCreationException;
import rs.ac.singidunum.tokenmanager.config.AppConfig;
import rs.ac.singidunum.tokenmanager.config.HttpApiServer;
import rs.ac.singidunum.tokenmanager.services.TokenService;
import rs.ac.singidunum.tokenmanager.ui.PinDialog;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class App extends Application {
    @Override
    public void start(Stage stage) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException {

        // Load Config
        AppConfig appConfig = AppConfig.getInstance();

        // Initialize TokenService
        TokenService tokenService = new TokenService(appConfig);
        //tokenService.generateLocalToken("Teodor-New", "1234");

        // Start HTTP Server
        HttpApiServer server = new HttpApiServer(appConfig, tokenService, () -> requestPin(stage));
        server.start();

        // Building the UI and Display
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource("main-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 320, 240);
        stage.setTitle("Token Manager");
        stage.setScene(scene);
//        scene.getStylesheets().setAll(
//                Objects.requireNonNull(App.class.getResource("style.css")).toExternalForm(),
//                Objects.requireNonNull(App.class.getResource("light-theme.css")).toExternalForm()
//        );
        stage.show();
    }

    private String requestPin(Stage owner) {
        if (Platform.isFxApplicationThread()) {
            return new PinDialog(owner).showAndGet().orElse(null);
        }


        CompletableFuture<String> pinFuture = new CompletableFuture<>();
        Platform.runLater(() -> {
            pinFuture.complete(new PinDialog(owner).showAndGet().orElse(null));
        });

        try {
            return pinFuture.get();
        } catch (ExecutionException | InterruptedException e) {
            return null;
        }
    }
}
