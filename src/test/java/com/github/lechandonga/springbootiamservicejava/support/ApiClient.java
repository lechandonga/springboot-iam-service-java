package com.github.lechandonga.springbootiamservicejava.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import java.time.Duration;

/**
 * Minimal JSON HTTP client for the integration tests.
 */
public class ApiClient {

    public record Response(int status, JsonNode json) {
        public String code() {
            return json.path("code").asText("");
        }
    }

    private final String baseUrl;
    private final ObjectMapper objectMapper;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public ApiClient(int port, ObjectMapper objectMapper) {
        this.baseUrl = "http://localhost:" + port;
        this.objectMapper = objectMapper;
    }

    public Response post(String path, Object body) {
        return send("POST", path, body, null);
    }

    public Response post(String path, Object body, String bearer) {
        return send("POST", path, body, bearer);
    }

    public Response get(String path, String bearer) {
        return send("GET", path, null, bearer);
    }

    public Response put(String path, Object body, String bearer) {
        return send("PUT", path, body, bearer);
    }

    public Response delete(String path, String bearer) {
        return send("DELETE", path, null, bearer);
    }

    private Response send(String method, String path, Object body, String bearer) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(20))
                    .header("Content-Type", "application/json");
            if (bearer != null) {
                builder.header("Authorization", "Bearer " + bearer);
            }
            HttpRequest.BodyPublisher publisher = body == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body));
            builder.method(method, publisher);
            HttpResponse<String> response = http.send(builder.build(),
                    HttpResponse.BodyHandlers.ofString());
            JsonNode json = response.body().isBlank()
                    ? objectMapper.createObjectNode()
                    : objectMapper.readTree(response.body());
            return new Response(response.statusCode(), json);
        } catch (Exception e) {
            throw new IllegalStateException("HTTP call failed: " + method + " " + path, e);
        }
    }
}
