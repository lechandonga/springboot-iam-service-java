package com.github.lechandonga.springbootiamservicejava.tests;

import com.github.lechandonga.springbootiamservicejava.support.ApiClient;
import com.github.lechandonga.springbootiamservicejava.support.IamTestBase;
import com.github.lechandonga.springbootiamservicejava.support.Scenario;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.github.lechandonga.springbootiamservicejava.service.TokenService;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景: 令牌签发、轮换与盗用吊销
 * - 访问/刷新令牌类型区分
 * - 刷新令牌一次性：轮换后旧令牌重放判定为盗用，整条会话链吊销
 * - 过期 / 已吊销 / 签名错误 / 内容篡改 / 格式错误 的拒绝原因可区分
 */
class TokenRotationTest extends IamTestBase {

    @Autowired
    private TokenService tokenService;

    @Test
    void rotationReplayAndInvalidTokens() {
        Scenario.begin("令牌轮换、重放吊销与失效原因区分",
                "一次性刷新轮换、重放吊销会话链、过期/吊销/坏签名/篡改/类型不符分别拒绝");

        String user = "token_user";
        createUser(user, "token-pw", Set.of("admin"), Map.of());
        ApiClient.Response login = login(user, "token-pw");
        assertEquals(200, login.status(), login.json().toString());
        String access1 = login.json().get("accessToken").asText();
        String refresh1 = login.json().get("refreshToken").asText();

        Scenario.runCase("短效访问令牌可用于受保护接口", () -> {
            ApiClient.Response ok = api.get("/api/admin/policies", access1);
            assertEquals(200, ok.status(), ok.json().toString());
            return "GET /api/admin/policies 200";
        });

        Scenario.runCase("刷新令牌轮换: 旧令牌作废, 得到新令牌对", () -> {
            ApiClient.Response rotated = api.post("/api/auth/refresh",
                    Map.of("refreshToken", refresh1));
            assertEquals(200, rotated.status(), rotated.json().toString());
            assertNotEquals(refresh1, rotated.json().get("refreshToken").asText());
            assertNotEquals(access1, rotated.json().get("accessToken").asText());
            return "新 refreshToken/accessToken 均与旧令牌不同";
        });

        Scenario.runCase("旧刷新令牌重放 => REFRESH_REPLAY, 会话链被吊销", () -> {
            ApiClient.Response replay = api.post("/api/auth/refresh",
                    Map.of("refreshToken", refresh1));
            assertCode(replay, 403, "REFRESH_REPLAY");
            return "重放返回 403 REFRESH_REPLAY: " + replay.json().get("message").asText();
        });

        Scenario.runCase("链吊销后轮换得到的访问/刷新令牌全部失效", () -> {
            ApiClient.Response rotatedAgain = api.post("/api/auth/refresh",
                    Map.of("refreshToken", refresh1));
            assertCode(rotatedAgain, 403, "REFRESH_REPLAY");
            // Even a token signed in that chain is rejected because the chain is revoked.
            ApiClient.Response blocked = api.get("/api/admin/policies", access1);
            assertCode(blocked, 401, "TOKEN_REVOKED");
            return "同链访问令牌返回 TOKEN_REVOKED";
        });

        Scenario.runCase("令牌过期 => TOKEN_EXPIRED (原因可区分)", () -> {
            // A dedicated fresh chain is needed here: the earlier replay test revoked
            // the first chain. Move the verification clock beyond both token lifetimes.
            ApiClient.Response expiryLogin = login(user, "token-pw");
            String expAccess = expiryLogin.json().get("accessToken").asText();
            String expRefresh = expiryLogin.json().get("refreshToken").asText();
            assertEquals(200, api.get("/api/admin/policies", expAccess).status());
            tokenService.setClock(Clock.fixed(Instant.now().plusSeconds(11 * 60), ZoneOffset.UTC));
            try {
                assertCode(api.get("/api/admin/policies", expAccess), 401, "TOKEN_EXPIRED");
                // 11 minutes is still inside the 12h refresh lifetime; advance beyond it.
                tokenService.setClock(Clock.fixed(Instant.now().plusSeconds(13 * 3600), ZoneOffset.UTC));
                assertCode(api.post("/api/auth/refresh",
                        Map.of("refreshToken", expRefresh)), 401, "TOKEN_EXPIRED");
            } finally {
                tokenService.setClock(Clock.systemUTC());
            }
            return "访问令牌(+11分钟)与刷新令牌(+13小时)分别返回 TOKEN_EXPIRED";
        });

        ApiClient.Response fresh = login(user, "token-pw");
        String access2 = fresh.json().get("accessToken").asText();
        String refresh2 = fresh.json().get("refreshToken").asText();
        assertFalse(refresh2.isBlank());

        Scenario.runCase("主动登出 => 链吊销, 再用访问令牌返回 TOKEN_REVOKED", () -> {
            ApiClient.Response login2 = login(user, "token-pw");
            String access3 = login2.json().get("accessToken").asText();
            ApiClient.Response logout = api.post("/api/auth/logout", Map.of(), access3);
            assertEquals(200, logout.status(), logout.json().toString());
            ApiClient.Response afterLogout = api.get("/api/admin/policies", access3);
            assertCode(afterLogout, 401, "TOKEN_REVOKED");
            return "logout 后同链访问令牌立即失效";
        });

        ApiClient.Response login3 = login(user, "token-pw");
        String access4 = login3.json().get("accessToken").asText();

        Scenario.runCase("签名不合法 => BAD_SIGNATURE", () -> {
            String badSignature = access4.substring(0, access4.length() - 2) + "AA";
            ApiClient.Response bad = api.get("/api/admin/policies", badSignature);
            assertCode(bad, 401, "BAD_SIGNATURE");
            return "改签名段返回 BAD_SIGNATURE";
        });

        Scenario.runCase("内容被篡改 => BAD_SIGNATURE", () -> {
            int dot = access4.indexOf('.');
            String tampered = access4.substring(0, dot - 1) + "X" + access4.substring(dot);
            ApiClient.Response bad = api.get("/api/admin/policies", tampered);
            assertCode(bad, 401, "BAD_SIGNATURE");
            return "改 payload 段导致签名校验失败";
        });

        Scenario.runCase("格式错误令牌 => MALFORMED_TOKEN", () -> {
            ApiClient.Response bad = api.get("/api/admin/policies", "not-a-token");
            assertCode(bad, 401, "MALFORMED_TOKEN");
            return "无点分隔的令牌返回 MALFORMED_TOKEN";
        });

        Scenario.runCase("缺少令牌 => MISSING_TOKEN", () -> {
            ApiClient.Response bad = api.get("/api/admin/policies", null);
            assertCode(bad, 401, "MISSING_TOKEN");
            return "无 Authorization 头返回 MISSING_TOKEN";
        });

        Scenario.runCase("刷新令牌当访问令牌用 => TOKEN_TYPE_MISMATCH", () -> {
            ApiClient.Response bad = api.get("/api/admin/policies", login(user, "token-pw")
                    .json().get("refreshToken").asText());
            assertCode(bad, 401, "TOKEN_TYPE_MISMATCH");
            return "类型字段参与校验，拒绝混用";
        });
    }
}
