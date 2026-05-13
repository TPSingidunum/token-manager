module rs.ac.singidunum.tokenmanager {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.web;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;
    requires net.synedra.validatorfx;
    requires org.kordamp.ikonli.javafx;
    requires org.kordamp.bootstrapfx.core;
    requires eu.hansolo.tilesfx;
    requires com.almasb.fxgl.all;

    opens rs.ac.singidunum.tokenmanager to javafx.fxml;
    exports rs.ac.singidunum.tokenmanager;
    exports rs.ac.singidunum.tokenmanager.controllers;
    opens rs.ac.singidunum.tokenmanager.controllers to javafx.fxml;
}