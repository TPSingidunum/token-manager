package rs.ac.singidunum.tokenmanager;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import rs.ac.singidunum.tokenmanager.config.AppConfig;

import java.io.IOException;

public class App extends Application {
    @Override
    public void start(Stage stage) throws IOException {

        // Load Config
        AppConfig appConfig = AppConfig.getInstance();
        System.out.println("Server port: " + appConfig.getProperty(AppConfig.SERVER_PORT));


        // Start HTTP Server


        // Building the UI and Display
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource("main-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 320, 240);
        stage.setTitle("Token Manager");
        stage.setScene(scene);
        stage.show();
    }
}
