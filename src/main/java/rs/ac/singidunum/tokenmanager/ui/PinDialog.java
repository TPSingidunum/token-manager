package rs.ac.singidunum.tokenmanager.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;

public class PinDialog extends PopupWindow<String>{
    private final PasswordField pinField = new PasswordField();
    private final Label errorLabel = new Label();

    public PinDialog(Stage owner) {
        super(owner, "Enter pin:", 360,200);

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        //grid.setPadding(new Insets(18,22,10,22));

        pinField.setPromptText("Enter pin");
        pinField.setPrefWidth(300);

        Label pinLabel = new Label("Pin:");

        grid.addRow(0, pinLabel, pinField);
        grid.add(errorLabel, 0,1,2,1);

        setBody(grid);

        Button cancelButton = new Button("Cancel");
        cancelButton.setOnAction(event -> stage.close());

        Button okButton = new Button("Enter");
        okButton.setDefaultButton(true);
        okButton.setOnAction(event -> {
            if(!pinField.getText().matches("\\d{4}")) {
                errorLabel.setText("Invalid pin format");
                return;
            }

            closeWithResult(pinField.getText());
        });

        HBox footer = new HBox(10);
        footer.setAlignment(Pos.CENTER_RIGHT);
        footer.getChildren().addAll(okButton, cancelButton);

        setFooter(footer);
    }
}
