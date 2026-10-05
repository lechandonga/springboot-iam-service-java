package com.github.lechandonga.springbootiamservicejava.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Shared full-stack test setup: boots the service on a random port, logs in
 * the seeded admin, and exposes a JSON {@link ApiClient}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class IamTestBase {

    @LocalServerPort
    protected int port;

    @Autowired
    protected ObjectMapper objectMapper;

    protected ApiClient api;
    protected String adminAccess;

    @BeforeAll
    void setUpClient() {
        api = new ApiClient(port, objectMapper);
        ApiClient.Response login = api.post("/api/auth/login",
                Map.of("username", "admin", "password", "admin123"));
        assertEquals(200, login.status(), "admin login should succeed: " + login.json());
        adminAccess = login.json().get("accessToken").asText();
    }

    protected String createUser(String username, String password, Set<String> roles,
                                Map<String, String> attributes) {
        Map<String, Object> body = new java.util.HashMap<>();
        body.put("username", username);
        body.put("password", password);
        body.put("roles", roles);
        body.put("attributes", attributes == null ? Map.of() : attributes);
        ApiClient.Response response = api.post("/api/admin/accounts", body, adminAccess);
        assertEquals(200, response.status(), "create user: " + response.json());
        return username;
    }

    protected ApiClient.Response login(String username, String password) {
        return api.post("/api/auth/login", Map.of("username", username, "password", password));
    }

    protected void assertCode(ApiClient.Response response, int status, String code) {
        assertEquals(status, response.status(),
                "expected HTTP " + status + " but got " + response.status() + ": " + response.json());
        assertEquals(code, response.code(),
                "expected error code " + code + " but got: " + response.json());
    }
}
