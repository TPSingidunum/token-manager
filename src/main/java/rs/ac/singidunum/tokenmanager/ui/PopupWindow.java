package rs.ac.singidunum.tokenmanager.ui;

import javafx.animation.FadeTransition;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.Duration;

import java.util.Optional;

public abstract class PopupWindow<T> {
    protected final Stage stage;
    protected final BorderPane root;

    private T result;
    private double dragOffsetX;
    private double dragOffsetY;

    protected PopupWindow(Stage owner, String title, double width, double height) {
        stage = new Stage(StageStyle.UNDECORATED);
        stage.initModality(Modality.WINDOW_MODAL);
        if (owner != null) {
            stage.initOwner(owner);
        }
        stage.setResizable(false);

        root = new BorderPane();
        root.getStyleClass().add("popup-root");

        HBox header = buildHeader(title);
        root.setTop(header);
        wireDrag(header);

        Scene scene = new Scene(root, width, height);
        scene.setOnKeyPressed(event -> {
            if (event.getCode() == KeyCode.ESCAPE) {
                stage.close();
                event.consume();
            }
        });

        stage.setOnShown(event -> {
            root.setOpacity(0);
            FadeTransition fade = new FadeTransition(Duration.millis(140), root);
            fade.setFromValue(0);
            fade.setToValue(1);
            fade.play();
        });

        stage.setScene(scene);
    }

    private HBox buildHeader(String title) {
        Label titleLabel = new Label(title);
        titleLabel.getStyleClass().add("popup-title");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button closeButton = new Button("×");
        closeButton.getStyleClass().addAll("window-btn", "popup-close-btn");
        closeButton.setOnAction(event -> stage.close());

        HBox header = new HBox(titleLabel, spacer, closeButton);
        header.setAlignment(Pos.CENTER_LEFT);
        header.getStyleClass().add("popup-header");
        return header;
    }

    protected void setBody(Node body) {
        if (body != null && !body.getStyleClass().contains("popup-body")) {
            body.getStyleClass().add("popup-body");
        }
        root.setCenter(body);
    }

    protected void setFooter(Node footer) {
        if (footer != null && !footer.getStyleClass().contains("popup-footer")) {
            footer.getStyleClass().add("popup-footer");
        }
        root.setBottom(footer);
    }

    protected void closeWithResult(T value) {
        result = value;
        stage.close();
    }

    public Optional<T> showAndGet() {
        result = null;
        stage.showAndWait();
        return Optional.ofNullable(result);
    }

    public Optional<T> showAndWait() {
        return showAndGet();
    }

    private void wireDrag(Node dragNode) {
        dragNode.setOnMousePressed(event -> {
            dragOffsetX = event.getScreenX() - stage.getX();
            dragOffsetY = event.getScreenY() - stage.getY();
        });
        dragNode.setOnMouseDragged(event -> {
            stage.setX(event.getScreenX() - dragOffsetX);
            stage.setY(event.getScreenY() - dragOffsetY);
        });
    }
}


