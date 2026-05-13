package rs.ac.singidunum.tokenmanager.controllers;

import javafx.fxml.FXML;
import javafx.scene.control.Label;

public class TokenController {
    @FXML
    private Label welcomeText;

    @FXML
    protected void onHelloButtonClick() {
        welcomeText.setText("Welcome to JavaFX Application!");
    }
}
