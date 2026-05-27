package rs.ac.singidunum.tokenmanager.ui;

import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;
import rs.ac.singidunum.tokenmanager.config.AppConfig;
import rs.ac.singidunum.tokenmanager.services.TokenService;

import java.security.PrivateKey;

public class AddLocalTokenDialog extends PopupWindow<String>{
    private final TextField nameField = new TextField();
    private final Label errorLabel = new Label();

    public AddLocalTokenDialog(Stage owner) {
        super(owner, "Enter Token name:", 360,200);

        AppConfig appConfig = AppConfig.getInstance();
        TokenService tokenService = new TokenService(appConfig);

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        //grid.setPadding(new Insets(18,22,10,22));

        nameField.setPromptText("Enter name:");
        nameField.setPrefWidth(300);

        Label pinLabel = new Label("Name:");

        grid.addRow(0, pinLabel, nameField);
        grid.add(errorLabel, 0,1,2,1);

        setBody(grid);

        Button cancelButton = new Button("Cancel");
        cancelButton.setOnAction(event -> stage.close());

        Button okButton = new Button("Enter");
        okButton.setDefaultButton(true);
        okButton.setOnAction(event -> {

            if(!nameField.getText().matches("[a-zA-Z0-9]{4,12}")) {
                errorLabel.setText("Invalid name");
                return;
            }

            // Proveriti da li imamo konflik imena tokena

            closeWithResult(nameField.getText());
        });

        HBox footer = new HBox(10);
        footer.setAlignment(Pos.CENTER_RIGHT);
        footer.getChildren().addAll(okButton, cancelButton);

        setFooter(footer);
    }
}
