module com.example.tokenmanager {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;
    requires net.synedra.validatorfx;
    requires org.kordamp.ikonli.javafx;
    requires org.kordamp.bootstrapfx.core;
    requires com.dustinredmond.fxtrayicon;
    requires jdk.compiler;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires jdk.httpserver;
    requires java.net.http;

    opens com.example.tokenmanager to javafx.fxml;
    exports com.example.tokenmanager;

    opens com.example.tokenmanager.controllers to javafx.fxml;
    exports com.example.tokenmanager.controllers;

    opens com.example.tokenmanager.configs to javafx.fxml;
    exports com.example.tokenmanager.configs;

    opens com.example.tokenmanager.entities to javafx.fxml;
    exports com.example.tokenmanager.entities;

    opens com.example.tokenmanager.ui to javafx.fxml;
    exports com.example.tokenmanager.ui;
}