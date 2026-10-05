package com.github.lechandonga.springbootiamservicejava.tests.iam;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/** 场景一：账号凭证校验与失败锁定主流程。 */
class AuthenticationLockTests extends IamTestBase {

    @Test
    void credential_errors_are_distinguishable_and_lock_kicks_in() {
        ScenarioLog.scenario("认证与锁定：错误原因区分 + 连续失败锁定");
        String admin = adminToken();
        createUser(admin, "lock_user", "right-pass-123", List.of("viewer"), List.of());

        ScenarioLog.step("错误口令登录", "返回 INVALID_CREDENTIALS，不透出底层异常");
        assertError(post("/api/auth/login", null, Map.of("username", "lock_user", "password", "WRONG")),
                HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
        ScenarioLog.pass("错误口令被拒绝，错误码 INVALID_CREDENTIALS");

        ScenarioLog.step("不存在的账号登录", "同样返回 INVALID_CREDENTIALS（不暴露账号是否存在）");
        assertError(post("/api/auth/login", null, Map.of("username", "ghost", "password", "whatever")),
                HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
        ScenarioLog.pass("未知账号与坏口令错误码一致");

        ScenarioLog.step("连续失败达到阈值 5 次（前面已失败 1 次）", "第 5 次失败即锁定，之后连正确口令都被拒为 ACCOUNT_LOCKED");
        for (int i = 0; i < 3; i++) {
            assertError(post("/api/auth/login", null, Map.of("username", "lock_user", "password", "bad")),
                    HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
        }
        // 第 5 次失败：本次仍是凭证错误，同时账号被锁定
        assertError(post("/api/auth/login", null, Map.of("username", "lock_user", "password", "bad")),
                HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
        ScenarioLog.pass("5 次失败均返回 INVALID_CREDENTIALS，且第 5 次触发锁定");
        assertError(post("/api/auth/login", null,
                        Map.of("username", "lock_user", "password", "right-pass-123")),
                HttpStatus.LOCKED, "ACCOUNT_LOCKED");
        ScenarioLog.pass("阈值锁定生效，锁定原因 ACCOUNT_LOCKED 可与凭证错误区分");

        ScenarioLog.step("管理员解锁", "解锁后正确口令可以登录");
        assertEquals(200, post("/api/admin/accounts/lock_user/unlock", admin, Map.of()).status());
        assertNotNull(login("lock_user", "right-pass-123").get("accessToken"));
        ScenarioLog.pass("解锁后登录成功");

        ScenarioLog.step("被禁用账号登录", "返回 ACCOUNT_DISABLED");
        createUser(admin, "disabled_user", "disabled-pass-1", List.of("viewer"), List.of(), false);
        assertError(post("/api/auth/login", null,
                        Map.of("username", "disabled_user", "password", "disabled-pass-1")),
                HttpStatus.FORBIDDEN, "ACCOUNT_DISABLED");
        ScenarioLog.pass("禁用账号错误码 ACCOUNT_DISABLED（种子账号 dave 同样被禁用）");
    }
}
