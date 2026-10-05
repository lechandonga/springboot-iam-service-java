package com.github.lechandonga.springbootiamservicejava.tests;

import com.github.lechandonga.springbootiamservicejava.support.ApiClient;
import com.github.lechandonga.springbootiamservicejava.support.IamTestBase;
import com.github.lechandonga.springbootiamservicejava.support.Scenario;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景: 授权默认拒绝、最小权限、角色与账号属性联合判定，
 * 以及账号禁用 / 权限调整对“已签发会话”立即生效。
 */
class AuthorizationLiveChangeTest extends IamTestBase {

    @Test
    void defaultDenyRolesAttributesAndLiveChanges() {
        Scenario.begin("授权判定与权限/状态即时生效",
                "默认拒绝、角色+属性联合匹配、撤销角色与禁用账号对存量会话立即生效");

        Scenario.runCase("新账号默认无权限: 任意操作默认拒绝", () -> {
            createUser("authz_nobody", "pw", Set.of(), Map.of());
            ApiClient.Response login = login("authz_nobody", "pw");
            String token = login.json().get("accessToken").asText();
            ApiClient.Response denied = api.post("/api/resource/access",
                    Map.of("resource", "document", "action", "read"), token);
            assertEquals(403, denied.status(), denied.json().toString());
            assertFalse(denied.json().get("allowed").asBoolean());
            assertTrue(denied.json().get("detail").asText().contains("default-deny"),
                    "应记录默认拒绝依据: " + denied.json());
            return "无匹配策略 => ALLOWED=false, detail 含 default-deny";
        });

        Scenario.runCase("属性策略: engineering 部门可读文档 (非角色)", () -> {
            createUser("authz_eng", "pw", Set.of("viewer"), Map.of("department", "engineering"));
            String token = login("authz_eng", "pw").json().get("accessToken").asText();
            ApiClient.Response allowed = api.post("/api/resource/access",
                    Map.of("resource", "document", "action", "read"), token);
            assertEquals(200, allowed.status(), allowed.json().toString());
            assertTrue(allowed.json().get("allowed").asBoolean());
            assertTrue(allowed.json().get("detail").asText().contains("p-doc-read-eng"));
            // Least privilege: read allowed, write not.
            ApiClient.Response writeDenied = api.post("/api/resource/access",
                    Map.of("resource", "document", "action", "write"), token);
            assertEquals(403, writeDenied.status());
            return "read ALLOW(p-doc-read-eng), write 默认拒绝";
        });

        Scenario.runCase("marketing 部门 + viewer 角色读文档被拒绝 (属性不匹配)", () -> {
            createUser("authz_mkt", "pw", Set.of("viewer"), Map.of("department", "marketing"));
            String token = login("authz_mkt", "pw").json().get("accessToken").asText();
            ApiClient.Response denied = api.post("/api/resource/access",
                    Map.of("resource", "document", "action", "read"), token);
            assertEquals(403, denied.status());
            return "角色相同但属性不满足，依然拒绝";
        });

        Scenario.runCase("具体受保护操作 /documents/write 由同一引擎把关", () -> {
            createUser("authz_editor", "pw", Set.of("editor"), Map.of("department", "marketing"));
            String token = login("authz_editor", "pw").json().get("accessToken").asText();
            ApiClient.Response write = api.post("/api/resource/documents/write", Map.of(), token);
            assertEquals(200, write.status(), write.json().toString());
            ApiClient.Response read = api.post("/api/resource/documents/read", Map.of(), token);
            assertEquals(403, read.status());
            return "editor 可 write(p-doc-write-editor), 不可 read";
        });

        Scenario.runCase("角色被撤销后, 已签发访问令牌立刻失去权限", () -> {
            createUser("authz_role_victim", "pw", Set.of("editor"), Map.of("department", "marketing"));
            String token = login("authz_role_victim", "pw").json().get("accessToken").asText();
            assertEquals(200, api.post("/api/resource/documents/write", Map.of(), token).status());
            ApiClient.Response revoke = api.put("/api/admin/accounts/authz_role_victim/roles",
                    Map.of("roles", List.of()), adminAccess);
            assertEquals(200, revoke.status(), revoke.json().toString());
            ApiClient.Response after = api.post("/api/resource/documents/write", Map.of(), token);
            assertCode(after, 403, "ACCESS_DENIED");
            return "未换令牌，同一请求从 200 变为 ACCESS_DENIED（授权实时读取角色）";
        });

        Scenario.runCase("账号被禁用后, 已签发访问令牌立刻被拒绝", () -> {
            createUser("authz_disable_victim2", "pw", Set.of("editor"), Map.of("department", "marketing"));
            String token = login("authz_disable_victim2", "pw").json().get("accessToken").asText();
            assertEquals(200, api.post("/api/resource/documents/write", Map.of(), token).status());
            api.put("/api/admin/accounts/authz_disable_victim2/enabled",
                    Map.of("enabled", false), adminAccess);
            ApiClient.Response after = api.post("/api/resource/documents/write", Map.of(), token);
            assertCode(after, 403, "ACCOUNT_DISABLED");
            return "禁用即时生效，过滤器层直接返回 ACCOUNT_DISABLED";
        });

        Scenario.runCase("DENY 策略优先: 显式拒绝压过通配 ALLOW", () -> {
            createUser("authz_deny_victim", "pw", Set.of("admin"), Map.of());
            String token = login("authz_deny_victim", "pw").json().get("accessToken").asText();
            // Before: admin can manage policies.
            assertEquals(200, api.get("/api/admin/policies", token).status());
            // Add high-priority DENY for this user.
            ApiClient.Response policy = api.post("/api/admin/policies", Map.of(
                    "id", "p-deny-authz-victim",
                    "subject", "user:authz_deny_victim",
                    "resource", "admin:policy",
                    "action", "*",
                    "effect", "DENY",
                    "priority", 5), adminAccess);
            assertEquals(200, policy.status(), policy.json().toString());
            ApiClient.Response denied = api.get("/api/admin/policies", token);
            assertCode(denied, 403, "ACCESS_DENIED");
            return "priority=5 的 DENY 优先于 p-admin(priority=10)";
        });
    }
}
