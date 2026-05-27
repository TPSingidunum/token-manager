package rs.ac.singidunum.tokenmanager.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class EntropyStage extends Stage {
    private final ByteArrayOutputStream data = new ByteArrayOutputStream();
    private final ProgressBar progressBar = new ProgressBar(0);
    private final Label label = new Label("Move mouse to generate randomness - 0%");
    private final Canvas artCanvas = new Canvas(500, 400);
    private final int targetBytes = 4096;

    private final List<double[]> segments = new ArrayList<>();
    private boolean built;
    private int lastDrawn;

    private double dragOffsetX;
    private double dragOffsetY;

    public EntropyStage() {
        initStyle(StageStyle.UNDECORATED);

        BorderPane root = new BorderPane();
        root.getStyleClass().add("popup-root");

        HBox headerBar = createHeader();

        label.getStyleClass().add("entropy-label");
        VBox topBox = new VBox(headerBar, label);
        topBox.setPadding(new Insets(0, 20, 8, 20));
        root.setTop(topBox);

        BorderPane.setMargin(progressBar, new Insets(10, 20, 16, 20));
        progressBar.setPrefWidth(Double.MAX_VALUE);

        BorderPane.setMargin(artCanvas, new Insets(0, 20, 0, 20));
        root.setCenter(artCanvas);
        root.setBottom(progressBar);

        Scene scene = new Scene(root, 640, 560);

        scene.setOnMouseMoved(event -> {
            data.write((int) event.getX());
            data.write((int) event.getY());
            data.write((int) (event.getX() + event.getY()));
            data.write((int) (event.getX() * event.getY()));

            double progress = Math.min(1.0, (double) data.size() / targetBytes);
            progressBar.setProgress(progress);
            drawArt(progress);
            label.setText(String.format("Randomness: %.0f%%", progress * 100));

            if (data.size() >= targetBytes) {
                close();
            }
        });

        setScene(scene);
    }

    private HBox createHeader() {
        Label title = new Label("Collect Entropy");
        title.getStyleClass().add("popup-title");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button closeButton = new Button("×");
        closeButton.getStyleClass().addAll("window-btn", "popup-close-btn");
        closeButton.setOnAction(event -> close());

        HBox headerBar = new HBox(title, spacer, closeButton);
        headerBar.getStyleClass().add("popup-header");
        headerBar.setAlignment(Pos.CENTER_LEFT);
        wireDrag(headerBar);
        return headerBar;
    }

    private void wireDrag(HBox headerBar) {
        headerBar.setOnMousePressed(event -> {
            dragOffsetX = event.getScreenX() - getX();
            dragOffsetY = event.getScreenY() - getY();
        });
        headerBar.setOnMouseDragged(event -> {
            setX(event.getScreenX() - dragOffsetX);
            setY(event.getScreenY() - dragOffsetY);
        });
    }

    private void drawArt(double progress) {
        if (!built) {
            SecureRandom rng = new SecureRandom(data.toByteArray());
            generateSegments(rng,
                    artCanvas.getWidth() / 2,
                    artCanvas.getHeight() - 20,
                    artCanvas.getHeight() / 4 + rng.nextDouble() * 20,
                    -Math.PI / 2,
                    8);
            built = true;
        }

        int total = segments.size();
        int toDraw = Math.min(total, (int) (total * progress));
        GraphicsContext gc = artCanvas.getGraphicsContext2D();
        for (int i = lastDrawn; i < toDraw; i++) {
            double[] s = segments.get(i);
            gc.setStroke(Color.hsb((i / (double) total) * 360, 0.8, 0.8));
            gc.strokeLine(s[0], s[1], s[2], s[3]);
        }
        lastDrawn = toDraw;
    }

    private void generateSegments(Random rng, double x1, double y1,
                                  double length, double angle, int depth) {
        if (depth == 0) {
            return;
        }
        double x2 = x1 + length * Math.cos(angle);
        double y2 = y1 + length * Math.sin(angle);
        segments.add(new double[]{x1, y1, x2, y2});

        double split = (Math.PI / 6) * (0.8 + rng.nextDouble() * 0.4);
        double nextLen = length * (0.6 + rng.nextDouble() * 0.3);
        generateSegments(rng, x2, y2, nextLen, angle - split, depth - 1);
        generateSegments(rng, x2, y2, nextLen, angle + split, depth - 1);
    }

    public SecureRandom awaitRandom() {
        showAndWait();
        return new SecureRandom(data.toByteArray());
    }
}

