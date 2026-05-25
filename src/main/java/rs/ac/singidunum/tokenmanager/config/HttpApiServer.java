package rs.ac.singidunum.tokenmanager.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import rs.ac.singidunum.tokenmanager.dtos.ErrorResponse;
import rs.ac.singidunum.tokenmanager.dtos.HealthResponse;
import rs.ac.singidunum.tokenmanager.entities.Token;
import rs.ac.singidunum.tokenmanager.services.TokenService;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;

public class HttpApiServer {
    private AppConfig appConfig;
    private TokenService tokenService;
    private HttpServer server;
    private CorsFilter corsFilter;

    public HttpApiServer(AppConfig appConfig, TokenService tokenService) {
        this.appConfig = appConfig;
        this.tokenService = tokenService;
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
        server.createContext("/api/tokens", this::handleTokenList).getFilters().add(corsFilter);
        server.createContext("/api/public-key/", this::handleGetPublicKey).getFilters().add(corsFilter);
        server.createContext("/api/decrypt/file/", this::handleDecryptFile).getFilters().add(corsFilter);

        // Pokretanje servisa
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.start();

        System.out.println("Server started on port " + server.getAddress().getPort());
    }

    private void handleDecryptFile(HttpExchange he) throws IOException {
        String[] parts = he.getRequestURI().getPath().split("/");
        int fileId = Integer.parseInt(parts[parts.length - 1]);

        String auth = he.getRequestHeaders().getFirst("Authorization");
        if (auth == null) {
            System.out.println("Authorization header not found");
        } else {
            System.out.println("Authorization header found: " + auth);
        }

        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(appConfig.getProperty(AppConfig.BACKEND_URL) + "/api/storage/download/file/" + fileId))
                    .header("Authorization", he.getRequestHeaders().getFirst("Authorization"))
                    .GET()
                    .build();

            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());

            // FIX: Wrap the response body immediately.
            // If anything crashes below, this closes first and prevents the HttpClient from deadlocking.
            try (InputStream encryptedInputStream = response.body()) {

                if (response.statusCode() != 200) {
                    ErrorResponse error = new ErrorResponse("Failed to Send request");
                    sendResponseJson(he, 405, error.convertToJson());
                    return;
                }

                String headerEnvelopeKey = response.headers().firstValue("X-Envelope-Key").orElse(null);
                String headersIV = response.headers().firstValue("X-IV").orElse(null);
                String headersKeyId = response.headers().firstValue("X-Key-Id").orElse(null);

                if (headerEnvelopeKey == null || headersIV == null || headersKeyId == null) {
                    ErrorResponse error = new ErrorResponse("Failed to extract headers. Envelope: " + headerEnvelopeKey + ", IV: " + headersIV + ", keyId: " + headersKeyId);
                    sendResponseJson(he, 405, error.convertToJson());
                    return;
                }

                byte[] IV = Base64.getDecoder().decode(headersIV);
                System.out.println("IV length: " + IV.length);
                byte[] encodedKeyBytes = Base64.getDecoder().decode(headerEnvelopeKey);

                String pin = "1234";

                Optional<Token> token = tokenService.getTokenByKeyId(headersKeyId);
                if (token.isEmpty()) {
                    ErrorResponse error = new ErrorResponse("Token with keyId " + headersKeyId + " not found");
                    sendResponseJson(he, 405, error.convertToJson());
                    return;
                }

                PrivateKey privateKey = tokenService.decryptPrivateKey(token.get(), pin);
                SecretKey key = tokenService.decryptEnvelopeKey(encodedKeyBytes, privateKey);
                System.out.println("Secret key: " + key.getEncoded().length);

                System.out.println("Initializing cipher...");
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcm = new GCMParameterSpec(128, IV);
                cipher.init(Cipher.DECRYPT_MODE, key, gcm);
                System.out.println("Cipher initialized successfully!");

                Headers headers = he.getResponseHeaders();
                headers.set("Content-Type", response.headers().firstValue("Content-Type").orElse("application/octet-stream"));
                response.headers().firstValue("Content-Disposition").ifPresent(value -> {
                    headers.set("Content-Disposition", value);
                });

                he.sendResponseHeaders(200, 0);

                try (CipherInputStream decryptedInputStream = new CipherInputStream(encryptedInputStream, cipher);
                     OutputStream outputStream = he.getResponseBody()) {

                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = decryptedInputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                    outputStream.flush();
                }
            } // encryptedInputStream closes automatically here, breaking any network hang

        } catch (Throwable t) {
            // Catch absolutely EVERYTHING (Errors, RuntimeExceptions, etc.)
            System.err.println("!!! CRITICAL ERROR DETECTED !!!");
            t.printStackTrace(); // This will print your exact error to the console

            // Send the error back to the client so it doesn't hang either
            try {
                ErrorResponse error = new ErrorResponse("Server error: " + t.getMessage());
                sendResponseJson(he, 500, error.convertToJson());
            } catch (Exception ignored) {}

            throw new RuntimeException(t);
        }
    }


//    private void handleDecryptFile(HttpExchange he) throws IOException {
////        if(!he.getRequestMethod().equals("GET")) {
////            ErrorResponse error = new ErrorResponse("Method not supported");
////            sendResponseJson(he, 405, error.convertToJson());
////            return;
////        }
//
//        String[] parts = he.getRequestURI().getPath().split("/");
//        int fileId = Integer.parseInt(parts[parts.length - 1]);
//
//        String auth = he.getRequestHeaders().getFirst("Authorization");
//        if (auth == null) {
//            System.out.println("Authorization header not found");
//        } else {
//            System.out.println("Authorization header found: " + auth);
//        }
//
//        // Pitamo server za fajl i parametre potrebne za desifrovanje
//        try (HttpClient client = HttpClient.newHttpClient()) {
//            HttpRequest request = HttpRequest.newBuilder()
//                    .uri(URI.create(appConfig.getProperty(AppConfig.BACKEND_URL) + "/api/storage/download/file/" + fileId))
//                    .header("Authorization", he.getRequestHeaders().getFirst("Authorization"))
//                    .GET()
//                    .build();
//
//            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
//            if (response.statusCode() != 200) {
//                ErrorResponse error = new ErrorResponse("Failed to Send request");
//                sendResponseJson(he, 405, error.convertToJson());
//                return;
//            }
//
//            String headerEnvelopeKey = response.headers().firstValue("X-Envelope-Key").orElse(null);
//            String headersIV = response.headers().firstValue("X-IV").orElse(null);
//            String headersKeyId = response.headers().firstValue("X-Key-Id").orElse(null);
//
//            if (headerEnvelopeKey == null || headersIV == null || headersKeyId == null) {
//                ErrorResponse error = new ErrorResponse("Failed to extract headers. Envelope: " + headerEnvelopeKey + ", IV: " + headersIV + ", keyId: " + headersKeyId);
//                sendResponseJson(he, 405, error.convertToJson());
//                return;
//            }
//
//            byte[] IV = Base64.getDecoder().decode(headersIV);
//            System.out.println("IV: " + IV.length);
//            byte[] encodedKeyBytes =  Base64.getEncoder().encode(headersKeyId.getBytes(StandardCharsets.UTF_8));
//
//            // Middleware treda ba pita korisnika da unese pin da bi iskoristio sertifikat za desifrovanje fajla
//            String pin = "1234";
//
//            Optional<Token> token = tokenService.getTokenByKeyId(headersKeyId);
//
//            if (token.isEmpty()) {
//                ErrorResponse error = new ErrorResponse("Token with keyId " + headersKeyId + " not found");
//                sendResponseJson(he, 405, error.convertToJson());
//                return;
//            }
//
//            PrivateKey privateKey = tokenService.decryptPrivateKey(token.get(), pin);
//            SecretKey key = tokenService.decryptEnvelopeKey(encodedKeyBytes, privateKey);
//
//            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//            GCMParameterSpec gcm = new GCMParameterSpec(128,IV);
//            cipher.init(Cipher.DECRYPT_MODE, key, gcm);
//
//            Headers headers = he.getResponseHeaders();
//            headers.set("Content-Type", response.headers().firstValue("Content-Type").orElse("application/octet-stream"));
////            headers.set("Content-Disposition", String.valueOf(response.headers().firstValue("Content-Disposition")));
//            response.headers().firstValue("Content-Disposition").ifPresent(
//                    value -> headers.set("Content-Disposition", value)
//            );
//
//            he.sendResponseHeaders(200, 0);
//            try(
//                    InputStream encryptedInputStream = response.body();
//                    CipherInputStream decryptedInputStream = new CipherInputStream(encryptedInputStream, cipher);
//                    OutputStream outputStream = he.getResponseBody()
//            ) {
//                    byte[] buffer = new byte[4096];
//                    int bytesRead;
//                    while ((bytesRead = decryptedInputStream.read(buffer)) != -1) {
//                        outputStream.write(buffer, 0, bytesRead);
//                    }
//            }
//
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//
//    }

    private void handleGetPublicKey(HttpExchange he) throws IOException {
        if(!he.getRequestMethod().equals("GET")) {
            ErrorResponse error = new ErrorResponse("Method not supported");
            sendResponseJson(he, 405, error.convertToJson());
            return;
        }

        String[] parts = he.getRequestURI().getPath().split("/");
        String keyId = parts[parts.length - 1];
        String publicKeyPem = tokenService.getPublicKeyPemByKeyId(keyId);

        sendResponsePlain(he, 200, publicKeyPem);
    }

    private void handleTokenList(HttpExchange he) throws IOException {

        if(!he.getRequestMethod().equals("GET")) {
            ErrorResponse error = new ErrorResponse("Method not supported");
            sendResponseJson(he, 405, error.convertToJson());
            return;
        }

        String response = new ObjectMapper().writerFor(new TypeReference<List<Token>>() {})
                .writeValueAsString(tokenService.getTokens());

        sendResponseJson(he, 200, response);
    }

    private void handleHealth(HttpExchange he) throws IOException {

        if(!he.getRequestMethod().equals("GET")) {
            ErrorResponse error = new ErrorResponse("Method not supported");
            sendResponseJson(he, 405, error.convertToJson());
            return;
        }

        HealthResponse response = new HealthResponse("Alive");
        sendResponseJson(he, 200, response.convertToJson());
    }

    private void sendResponseJson(HttpExchange he, int status, String payload) throws IOException {
        byte[] body =  payload.getBytes(StandardCharsets.UTF_8);

        he.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        he.sendResponseHeaders(status, body.length);

        try (OutputStream os = he.getResponseBody()) {
            os.write(body);
            os.flush();
        }
    }

    private void sendResponsePlain(HttpExchange he, int status, String payload) throws IOException {
        byte[] body =  payload.getBytes(StandardCharsets.UTF_8);

        he.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        he.sendResponseHeaders(status, body.length);

        try (OutputStream os = he.getResponseBody()) {
            os.write(body);
            os.flush();
        }
    }
}
