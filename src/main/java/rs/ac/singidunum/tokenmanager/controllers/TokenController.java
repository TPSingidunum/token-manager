package rs.ac.singidunum.tokenmanager.controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.ListView;
import javafx.stage.Stage;
import org.bouncycastle.operator.OperatorCreationException;
import rs.ac.singidunum.tokenmanager.config.AppConfig;
import rs.ac.singidunum.tokenmanager.entities.Token;
import rs.ac.singidunum.tokenmanager.services.TokenService;
import rs.ac.singidunum.tokenmanager.ui.AddLocalTokenDialog;
import rs.ac.singidunum.tokenmanager.ui.EntropyStage;
import rs.ac.singidunum.tokenmanager.ui.PinDialogCreateToken;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.*;

public class TokenController {

    private AppConfig appConfig;
    private TokenService tokenService;

    @FXML
    public ListView<Token> tokenList;

    @FXML
    private void initialize() {
        this.appConfig = AppConfig.getInstance();
        this.tokenService = new  TokenService(appConfig);
        refreshTokenList();
    }

    @FXML
    public void onCreateToken(ActionEvent actionEvent) throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, NoSuchProviderException {
        Stage stage = (Stage) ((Node) actionEvent.getSource()).getScene().getWindow();

        AddLocalTokenDialog tokenName = new AddLocalTokenDialog(stage);
        Optional<String> result = tokenName.showAndGet();
        if (result.isEmpty()) {
            return;
        }

        PinDialogCreateToken tokenPin = new PinDialogCreateToken(stage);
        Optional<String> result2 = tokenPin.showAndGet();
        if (result2.isEmpty()) {
            return;
        }

        SecureRandom secure = new EntropyStage().awaitRandom();

        Token token = tokenService.generateLocalToken(result.get(), result2.get(), secure);
        tokenList.getItems().add(token);

    }

    public void refreshTokenList() {
        tokenList.getItems().setAll(
                tokenService.getTokens()
        );
    }
}
