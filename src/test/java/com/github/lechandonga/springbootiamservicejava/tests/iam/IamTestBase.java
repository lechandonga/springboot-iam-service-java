package com.github.lechandonga.springbootiamservicejava.tests.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 所有 IAM 场景测试的公共基类。
 * 测试环境使用 1s 访问令牌 / 2s 刷新令牌，便于本地确定性验证过期场景。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@org.springframework.test.context.TestPropertySource(properties = {
        "iam.access-token-ttl=10s",
        "iam.refresh-token-ttl=3s",
        "iam.max-failed-attempts=5",
        "iam.lock-duration=10m"
})
public abstract class IamTestBase {

    protected static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    protected TestRestTemplate rest;

    protected record ApiResponse(int status, String code, JsonNode body) {
        boolean is(String expectedCode) {
            return expectedCode.equals(code);
        }
    }

    protected ApiResponse post(String path, String bearer, Object request) {
        return exchange(HttpMethod.POST, path, bearer, request);
    }

    protected ApiResponse get(String path, String bearer) {
        return exchange(HttpMethod.GET, path, bearer, null);
    }

    private ApiResponse exchange(HttpMethod method, String path, String bearer, Object request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        try {
            HttpEntity<String> entity = new HttpEntity<>(
                    request == null ? null : MAPPER.writeValueAsString(request), headers);
            ResponseEntity<String> response = rest.exchange(path, method, entity, String.class);
            JsonNode body = response.getBody() == null ? null : MAPPER.readTree(response.getBody());
            String code = body != null && body.has("code") ? body.get("code").asText() : null;
            return new ApiResponse(response.getStatusCode().value(), code, body);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected JsonNode login(String username, String password) {
        ApiResponse response = post("/api/auth/login", null,
                java.util.Map.of("username", username, "password", password));
        assertEquals(200, response.status(), "登录应成功: " + username);
        return response.body();
    }

    protected String adminToken() {
        return login("admin", "admin-pass-123").get("accessToken").asText();
    }

    protected String createUser(String adminToken, String username, String password,
                                List<String> roles, List<String> attributes) {
        return createUser(adminToken, username, password, roles, attributes, true);
    }

    protected String createUser(String adminToken, String username, String password,
                                List<String> roles, List<String> attributes, boolean enabled) {
        ApiResponse response = post("/api/admin/accounts", adminToken, java.util.Map.of(
                "username", username,
                "password", password,
                "roles", roles,
                "attributes", attributes,
                "enabled", enabled));
        assertEquals(200, response.status(), "创建测试账号应成功: " + username);
        return username;
    }

    protected ApiResponse check(String token, String action) {
        return post("/api/protected/check", token, java.util.Map.of("action", action));
    }

    protected void assertError(ApiResponse response, HttpStatus status, String code) {
        assertEquals(status.value(), response.status(),
                "HTTP 状态码应为 " + status + "，响应: " + response.body());
        assertEquals(code, response.code, "错误码应为 " + code);
    }
}
