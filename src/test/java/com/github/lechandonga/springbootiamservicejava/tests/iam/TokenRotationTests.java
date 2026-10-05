package com.github.lechandonga.springbootiamservicejava.tests.iam;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/** 场景三：令牌签发、轮换、重放吊销与各类非法令牌拒绝。 */
class TokenRotationTests extends IamTestBase {

    @Test
    void refresh_rotation_replay_and_invalid_tokens() throws Exception {
        ScenarioLog.scenario("令牌：短效访问令牌 + 一次性刷新令牌轮换、重放即吊销会话链");
        String admin = adminToken();
        createUser(admin, "token_user", "token-pass-123", List.of("viewer"), List.of());
        JsonNode login = login("token_user", "token-pass-123");
        String accessToken = login.get("accessToken").asText();
        String refreshToken1 = login.get("refreshToken").asText();

        ScenarioLog.step("访问令牌访问受保护接口", "200 返回身份信息");
        assertEquals(200, get("/api/protected/profile", accessToken).status());
        ScenarioLog.pass("Bearer 访问令牌可用");

        ScenarioLog.step("无令牌 / 畸形令牌 / 坏签名 / 篡改内容", "分别返回 TOKEN_MISSING、TOKEN_MALFORMED、TOKEN_BAD_SIGNATURE");
        assertEquals(401, get("/api/protected/profile", null).status());
        assertEquals("TOKEN_MISSING", get("/api/protected/profile", null).code());
        String[] parts = accessToken.split("\\.");
        // 结构上根本不是令牌（无分隔点）
        assertError(get("/api/protected/profile", "not-a-jwt-ish-token"),
                HttpStatus.UNAUTHORIZED, "TOKEN_MALFORMED");
        // payload 段不是合法 base64url，同时签名也无法解析 -> 结构畸形
        assertError(get("/api/protected/profile", "@@@not-base64@@@." + parts[1]),
                HttpStatus.UNAUTHORIZED, "TOKEN_MALFORMED");
        // payload 合法、但签名长度与 HMAC 不符 -> 伪造的坏签名
        assertError(get("/api/protected/profile", parts[0] + "." + "ZmFrZXNpZw"),
                HttpStatus.UNAUTHORIZED, "TOKEN_BAD_SIGNATURE");
        // 保持签名长度、对 payload 内容做篡改 -> 验签失配，判定为内容篡改
        String tamperedPayload = tamperPayload(parts[0]);
        assertError(get("/api/protected/profile", tamperedPayload + "." + parts[1]),
                HttpStatus.UNAUTHORIZED, "TOKEN_TAMPERED");
        ScenarioLog.pass("畸形 / 坏签名 / 内容篡改三类拒绝原因均可区分");

        ScenarioLog.step("刷新令牌轮换", "旧刷新令牌作废，新访问令牌与新刷新令牌签发，且新令牌与旧的不同");
        JsonNode rotated1 = post("/api/auth/refresh", null,
                Map.of("refreshToken", refreshToken1)).body();
        String accessToken2 = rotated1.get("accessToken").asText();
        String refreshToken2 = rotated1.get("refreshToken").asText();
        assertNotEquals(refreshToken1, refreshToken2);
        assertNotEquals(accessToken, accessToken2);
        String session1 = login.get("sessionId").asText();
        assertEquals(session1, rotated1.get("sessionId").asText(), "轮换应保持同一会话链");
        assertEquals(200, get("/api/protected/profile", accessToken2).status());
        ScenarioLog.pass("刷新令牌用过即废并完成轮换，会话链 id 保持不变");

        ScenarioLog.step("重放旧刷新令牌（盗用）", "旧令牌被拒 TOKEN_REVOKED，且同会话链的新令牌全部被吊销");
        assertError(post("/api/auth/refresh", null, Map.of("refreshToken", refreshToken1)),
                HttpStatus.UNAUTHORIZED, "TOKEN_REVOKED");
        assertError(get("/api/protected/profile", accessToken2),
                HttpStatus.UNAUTHORIZED, "TOKEN_REVOKED");
        assertError(post("/api/auth/refresh", null, Map.of("refreshToken", refreshToken2)),
                HttpStatus.UNAUTHORIZED, "TOKEN_REVOKED");
        ScenarioLog.pass("重放即视为盗用，会话链上所有访问/刷新令牌被吊销");

        ScenarioLog.step("访问令牌过期(测试环境 TTL=10s，等待后确定性验证)", "返回 TOKEN_EXPIRED");
        Thread.sleep(10500);
        assertError(get("/api/protected/profile", accessToken),
                HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED");
        ScenarioLog.pass("过期访问令牌返回 TOKEN_EXPIRED");

        ScenarioLog.step("刷新令牌过期(测试环境 TTL=3s)", "返回 TOKEN_EXPIRED");
        JsonNode loginAgain = login("token_user", "token-pass-123");
        Thread.sleep(3300);
        assertError(post("/api/auth/refresh", null,
                        Map.of("refreshToken", loginAgain.get("refreshToken").asText())),
                HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED");
        ScenarioLog.pass("过期刷新令牌返回 TOKEN_EXPIRED");
    }

    private String tamperPayload(String payloadPart) {
        // 把 sub 字段的首字符替换为另一个用户名（admin 与 token_user 等长前缀替换），
        // base64url 层直接做等长字符替换后仍可解码为 JSON。
        String decoded = new String(java.util.Base64.getUrlDecoder().decode(payloadPart),
                java.nio.charset.StandardCharsets.UTF_8);
        String tampered = decoded.replace("\"sub\":\"token_user\"",
                "\"sub\":\"admin_xxxx\"");
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tampered.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
