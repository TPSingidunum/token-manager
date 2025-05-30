package com.example.tokenmanager.controllers;

import com.example.tokenmanager.configs.AppConfig;
import com.example.tokenmanager.configs.TokenManager;
import com.example.tokenmanager.entities.Token;
import com.example.tokenmanager.ui.AddTokenDialog;
import com.example.tokenmanager.ui.EntropyStage;
import com.example.tokenmanager.ui.PinDialog;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.ListView;
import org.bouncycastle.operator.OperatorCreationException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

public class MainController {
    private TokenManager tokenManager;
    private AppConfig appConfig = AppConfig.getInstance();

    @FXML
    public ListView<String> tokenList;

    public void setTokenManager(TokenManager tokenManager) {
        this.tokenManager = tokenManager;
        tokenList.getItems().setAll(tokenManager.getTokens().stream().map(Token::getName).toList());
    }

    @FXML
    public void onAddToken(ActionEvent actionEvent) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, OperatorCreationException, InvalidKeyException {

        AddTokenDialog addTokenDialog = new AddTokenDialog();
        Optional<AddTokenDialog.Result> optionalResult = addTokenDialog.showAndGet();
        if (optionalResult.isEmpty()) return;

        String name = optionalResult.get().name();
        String mode = optionalResult.get().mode();

        PinDialog pinDialog = new PinDialog();
        Optional<String> pin = pinDialog.showAndGet();
        if (pin.isEmpty()) return;

        String stringPin = pin.get();

        EntropyStage entropyStage = new EntropyStage();
        SecureRandom secureRandom = entropyStage.awaitRandom();
        Token token = tokenManager.generateToken(name, secureRandom, stringPin);

        Alert success = new Alert(Alert.AlertType.INFORMATION, "Token with name '" + name +"' has been created!!");
        success.show();
        tokenList.getItems().setAll(tokenManager.getTokens().stream().map(Token::getName).toList());
    }

    @FXML
    public void onChangeDirectory(ActionEvent actionEvent) {
    }
}
