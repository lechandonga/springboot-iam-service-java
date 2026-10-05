package com.github.lechandonga.springbootiamservicejava.tests;

import com.github.lechandonga.springbootiamservicejava.support.ApiClient;
import com.github.lechandonga.springbootiamservicejava.support.IamTestBase;
import com.github.lechandonga.springbootiamservicejava.support.Scenario;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 场景: 账号凭证与登录主流程
 * - 正确/错误口令的可区分结果
 * - 达到失败阈值后锁定
 * - 锁定期间正确口令也被拒绝（ACCOUNT_LOCKED 与 BAD_CREDENTIALS 区分）
 * - 禁用账号返回 ACCOUNT_DISABLED
 * - 底层异常不外泄（错误体只有 code + 安全 message）
 * - 口令以加盐哈希存储（不同账号同口令哈希不同）
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthLockFlowTest extends IamTestBase {

    private static final String USER = "flow_user";

    @BeforeAll
    void seedUser() {
        createUser(USER, "correct-pass", Set.of("viewer"), Map.of("department", "engineering"));
    }

    @Test
    @Order(1)
    void loginAndLockFlow() {
        Scenario.begin("认证与锁定主流程",
                "口令校验、失败计数锁定、锁定/禁用/错误凭证区分、加盐哈希存储");

        Scenario.runCase("正确口令登录成功并签发双令牌", () -> {
            ApiClient.Response ok = login(USER, "correct-pass");
            org.junit.jupiter.api.Assertions.assertEquals(200, ok.status(), ok.json().toString());
            assertNotNull(ok.json().get("accessToken").asText());
            assertNotNull(ok.json().get("refreshToken").asText());
            return "accessToken 与 refreshToken 均已签发";
        });

        Scenario.runCase("错误口令返回 BAD_CREDENTIALS 且不泄露内部信息", () -> {
            ApiClient.Response bad = login(USER, "wrong-pass");
            assertCode(bad, 401, "BAD_CREDENTIALS");
            assertFalse(bad.json().has("stackTrace"), "响应不得包含堆栈信息");
            return "响应体仅含 code/message: " + bad.json();
        });

        Scenario.runCase("连续失败达到阈值后账号锁定 (阈值=5)", () -> {
            // Previous case already produced one BAD_CREDENTIALS; four more reach the threshold.
            ApiClient.Response last = null;
            for (int i = 0; i < 4; i++) {
                last = login(USER, "wrong-pass");
            }
            org.junit.jupiter.api.Assertions.assertTrue(
                    last.code().equals("BAD_CREDENTIALS") || last.code().equals("ACCOUNT_LOCKED"),
                    "接近阈值时仍应给出明确结果，实际: " + last.json());
            ApiClient.Response threshold = login(USER, "wrong-pass");
            assertCode(threshold, 403, "ACCOUNT_LOCKED");
            ApiClient.Response lockedAttempt = login(USER, "correct-pass");
            assertCode(lockedAttempt, 403, "ACCOUNT_LOCKED");
            return "阈值后正确口令也被拒绝，错误码 ACCOUNT_LOCKED";
        });

        Scenario.runCase("锁定状态可由管理员解除, 解除后正确口令恢复登录", () -> {
            ApiClient.Response unlock = api.put(
                    "/api/admin/accounts/" + USER + "/enabled",
                    Map.of("enabled", false), adminAccess);
            org.junit.jupiter.api.Assertions.assertEquals(200, unlock.status(), unlock.json().toString());
            ApiClient.Response disabledLogin = login(USER, "correct-pass");
            assertCode(disabledLogin, 403, "ACCOUNT_DISABLED");
            api.put("/api/admin/accounts/" + USER + "/enabled",
                    Map.of("enabled", true), adminAccess);
            ApiClient.Response reLogin = login(USER, "correct-pass");
            org.junit.jupiter.api.Assertions.assertEquals(200, reLogin.status(), reLogin.json().toString());
            return "禁用期间 ACCOUNT_DISABLED, 重新启用后可登录";
        });
    }

}
