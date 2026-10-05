package com.github.lechandonga.springbootiamservicejava.tests.iam;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 场景五：账号禁用、角色/属性/口令调整后，已签发会话立即按新状态生效。 */
class ImmediateEffectTests extends IamTestBase {

    @Test
    void security_changes_invalidate_existing_sessions_immediately() {
        ScenarioLog.scenario("即时生效：禁用与权限调整后，已签发令牌立刻失效或按新状态判定");
        String admin = adminToken();
        createUser(admin, "effect_user", "effect-pass-1", List.of("editor"),
                List.of("department:content"));
        JsonNode login = login("effect_user", "effect-pass-1");
        String token = login.get("accessToken").asText();

        ScenarioLog.step("调整前", "editor 可以写文档");
        assertEquals(200, check(token, "document.write").status());
        ScenarioLog.pass("权限调整前写文档放行");

        ScenarioLog.step("管理员将角色降为 viewer", "旧访问令牌立即失效（TOKEN_REVOKED，安全版本不匹配）");
        ApiResponse update = post("/api/admin/accounts/effect_user", admin, Map.of(
                "roles", List.of("viewer"),
                "attributes", List.of("department:sales")));
        assertEquals(200, update.status());
        assertError(check(token, "document.write"), HttpStatus.UNAUTHORIZED, "TOKEN_REVOKED");
        ScenarioLog.pass("权限调整后旧令牌立即被拒，不再代表旧权限");

        ScenarioLog.step("重新登录后按新角色判定", "viewer 不能写文档，可读文档");
        String newToken = login("effect_user", "effect-pass-1").get("accessToken").asText();
        assertError(check(newToken, "document.write"), HttpStatus.FORBIDDEN, "ACCESS_DENIED");
        assertEquals(200, check(newToken, "document.read").status());
        ScenarioLog.pass("新会话严格按新角色/属性授权");

        ScenarioLog.step("管理员禁用账号", "已有令牌返回 ACCOUNT_DISABLED，刷新也被拒绝并吊销会话");
        assertEquals(200, post("/api/admin/accounts/effect_user", admin,
                Map.of("enabled", false)).status());
        assertError(get("/api/protected/profile", newToken),
                HttpStatus.FORBIDDEN, "ACCOUNT_DISABLED");
        assertError(post("/api/auth/login", null,
                        Map.of("username", "effect_user", "password", "effect-pass-1")),
                HttpStatus.FORBIDDEN, "ACCOUNT_DISABLED");
        ScenarioLog.pass("禁用即时生效：访问、登录均被区分性拒绝");

        ScenarioLog.step("种子账号 alice 改口令", "旧令牌立即失效，新口令可登录");
        String aliceToken = login("alice", "alice-pass-123").get("accessToken").asText();
        assertEquals(200, get("/api/protected/profile", aliceToken).status());
        assertEquals(200, post("/api/admin/accounts/alice", admin,
                Map.of("password", "alice-new-pass-1")).status());
        assertError(get("/api/protected/profile", aliceToken),
                HttpStatus.UNAUTHORIZED, "TOKEN_REVOKED");
        assertError(post("/api/auth/login", null,
                        Map.of("username", "alice", "password", "alice-pass-123")),
                HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
        assertEquals(200, post("/api/auth/login", null,
                Map.of("username", "alice", "password", "alice-new-pass-1")).status());
        ScenarioLog.pass("口令变更后旧会话失效，旧口令不可再用（恢复种子口令以便其他测试）");
        post("/api/admin/accounts/alice", admin, Map.of("password", "alice-pass-123"));
    }
}
