package rs.ac.singidunum.tokenmanager;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.operator.OperatorCreationException;
import rs.ac.singidunum.tokenmanager.config.AppConfig;
import rs.ac.singidunum.tokenmanager.config.HttpApiServer;
import rs.ac.singidunum.tokenmanager.services.TokenService;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public class App extends Application {
    @Override
    public void start(Stage stage) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException {

        // Load Config
        AppConfig appConfig = AppConfig.getInstance();

        // Initialize TokenService
        TokenService tokenService = new TokenService(appConfig);
        //tokenService.generateLocalToken("Teodor-New", "1234");

        // Start HTTP Server
        HttpApiServer server = new HttpApiServer(appConfig, tokenService);
        server.start();

        // Building the UI and Display
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource("main-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 320, 240);
        stage.setTitle("Token Manager");
        stage.setScene(scene);
        stage.show();
    }
}
