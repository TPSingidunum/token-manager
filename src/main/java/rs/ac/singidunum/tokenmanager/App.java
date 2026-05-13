package rs.ac.singidunum.tokenmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import rs.ac.singidunum.tokenmanager.config.AppConfig;
import rs.ac.singidunum.tokenmanager.config.HttpApiServer;
import rs.ac.singidunum.tokenmanager.dtos.HealthResponse;

import java.io.IOException;

public class App extends Application {
    @Override
    public void start(Stage stage) throws IOException {

        // Load Config
        AppConfig appConfig = AppConfig.getInstance();

        // Start HTTP Server
        HttpApiServer server = new HttpApiServer(appConfig);
        server.start();

        // Building the UI and Display
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource("main-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 320, 240);
        stage.setTitle("Token Manager");
        stage.setScene(scene);
        stage.show();
    }
}
