package com.example.tokenmanager;

import com.dustinredmond.fxtrayicon.FXTrayIcon;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.MenuItem;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.io.IOException;
import java.net.URL;

public class MainApp extends Application {
    private Stage primaryStage;
    private FXTrayIcon systemTray;
    public static String styleSheet = String.valueOf(MainApp.class.getResource("style.css"));
    public static URL imageUrl = MainApp.class.getResource("tray.png");

    @Override
    public void start(Stage stage) throws IOException {
        this.primaryStage = stage;

        FXMLLoader fxmlLoader = new FXMLLoader(MainApp.class.getResource("main-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load());
        scene.getStylesheets().add(styleSheet);

        primaryStage.setTitle("Token Manager");
        primaryStage.setScene(scene);
        primaryStage.setOnCloseRequest(this::hidePrimaryStage);
        primaryStage.show();

        systemTray();
    }

    public static void main(String[] args) {
        launch();
    }

    public void hidePrimaryStage(WindowEvent event) {
        event.consume();
        primaryStage.hide();
    }

    //TODO: Systemtray problem with java17
    private void systemTray() {
        systemTray = new FXTrayIcon(primaryStage, imageUrl);
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
}