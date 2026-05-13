package rs.ac.singidunum.tokenmanager.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import rs.ac.singidunum.tokenmanager.dtos.ErrorResponse;
import rs.ac.singidunum.tokenmanager.dtos.HealthResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

public class HttpApiServer {
    private AppConfig appConfig;
    // private TokenService tokenService;
    private HttpServer server;
    private CorsFilter corsFilter;

    public HttpApiServer(AppConfig appConfig) {
        this.appConfig = appConfig;
    }

    public void start() {
        try {
            server = HttpServer.create(
                    new InetSocketAddress(appConfig.getServerPort()), 0
            );
            corsFilter = new CorsFilter();
        } catch (IOException e) {
            System.out.println("Server start failed");
            throw new RuntimeException(e);
        }

        // Registracija Endpoint-ova
        server.createContext("/api/health", this::handleHealth).getFilters().add(corsFilter);

        // Pokretanje servisa
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.start();

        System.out.println("Server started on port " + server.getAddress().getPort());
    }

    private void handleHealth(HttpExchange he) throws IOException {
        // Logika funkcije
        System.out.println("Server received health request");

        if(!he.getRequestMethod().equals("GET")) {
            ErrorResponse error = new ErrorResponse("Method not supported");
            sendResponse(he, 405, error.convertToJson());
            return;
        }

        HealthResponse response = new HealthResponse("Alive");
        sendResponse(he, 200, response.convertToJson());
    }

    private void sendResponse(HttpExchange he, int status, String payload) throws IOException {
        byte[] body =  payload.getBytes(StandardCharsets.UTF_8);

        he.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        he.sendResponseHeaders(status, body.length);

        try (OutputStream os = he.getResponseBody()) {
            os.write(body);
            os.flush();
        }
    }
}
