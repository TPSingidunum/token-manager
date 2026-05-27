package rs.ac.singidunum.tokenmanager.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class NotificationDialog extends PopupWindow<Boolean> {

    public enum Type { INFO, SUCCESS, ERROR, WARNING }

    private NotificationDialog(Stage owner, Type type, String title, String message) {
        super(owner, "Notification", 440, 220);

        Label icon = new Label(iconFor(type));
        icon.getStyleClass().addAll("notification-icon", styleClassFor(type));

        Label titleLabel = new Label(title);
        titleLabel.getStyleClass().add("notification-title");
        titleLabel.setWrapText(true);

        Label messageLabel = new Label(message == null ? "" : message);
        messageLabel.getStyleClass().add("notification-message");
        messageLabel.setWrapText(true);
        messageLabel.setMaxWidth(340);

        VBox text = new VBox(6, titleLabel, messageLabel);
        text.setAlignment(Pos.TOP_LEFT);
        VBox.setVgrow(messageLabel, Priority.ALWAYS);

        HBox body = new HBox(16, icon, text);
        body.setAlignment(Pos.CENTER_LEFT);
        body.setPadding(new Insets(18, 24, 10, 24));
        HBox.setHgrow(text, Priority.ALWAYS);
        setBody(body);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button okButton = new Button("OK");
        okButton.getStyleClass().add("action-btn");
        okButton.setDefaultButton(true);
        okButton.setOnAction(event -> closeWithResult(Boolean.TRUE));

        HBox footer = new HBox(spacer, okButton);
        footer.setAlignment(Pos.CENTER_RIGHT);
        footer.setPadding(new Insets(8, 22, 16, 22));
        setFooter(footer);
    }

    // ── static factories ────────────────────────────────────────────────────

    public static NotificationDialog info(Stage owner, String title, String message) {
        return new NotificationDialog(owner, Type.INFO, title, message);
    }

    public static NotificationDialog success(Stage owner, String title, String message) {
        return new NotificationDialog(owner, Type.SUCCESS, title, message);
    }

    public static NotificationDialog error(Stage owner, String title, String message) {
        return new NotificationDialog(owner, Type.ERROR, title, message);
    }

    public static NotificationDialog warning(Stage owner, String title, String message) {
        return new NotificationDialog(owner, Type.WARNING, title, message);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private static String iconFor(Type type) {
        return switch (type) {
            case INFO    -> "ℹ";
            case SUCCESS -> "✔";
            case ERROR   -> "✖";
            case WARNING -> "⚠";
        };
    }

    private static String styleClassFor(Type type) {
        return switch (type) {
            case INFO    -> "notification-icon-info";
            case SUCCESS -> "notification-icon-success";
            case ERROR   -> "notification-icon-error";
            case WARNING -> "notification-icon-warning";
        };
    }
}
