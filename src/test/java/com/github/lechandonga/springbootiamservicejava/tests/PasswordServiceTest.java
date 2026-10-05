package com.github.lechandonga.springbootiamservicejava.tests;

import com.github.lechandonga.springbootiamservicejava.service.PasswordService;
import com.github.lechandonga.springbootiamservicejava.support.Scenario;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景: 凭证存储算法
 */
class PasswordServiceTest {

    private final PasswordService passwordService = new PasswordService();

    @Test
    void hashingIsSaltedOneWayAndVerifiable() {
        Scenario.begin("口令哈希算法",
                "PBKDF2 加盐、不可逆、同口令不同盐、错误口令不匹配、损坏存储安全失败");

        Scenario.runCase("哈希不是明文且可正确校验", () -> {
            String hash = passwordService.hash("hunter2");
            assertFalse(hash.contains("hunter2"));
            assertTrue(hash.startsWith("210000:"), "应包含迭代次数: " + hash);
            assertTrue(passwordService.matches("hunter2", hash));
            return "存储格式 iterations:salt:hash, 校验通过";
        });

        Scenario.runCase("同口令两次哈希因盐不同而不同", () -> {
            String h1 = passwordService.hash("same-password");
            String h2 = passwordService.hash("same-password");
            assertNotEquals(h1, h2);
            assertTrue(passwordService.matches("same-password", h1));
            assertTrue(passwordService.matches("same-password", h2));
            return "两条哈希均可独立校验，彩虹表预计算失效";
        });

        Scenario.runCase("错误口令与损坏存储安全返回 false", () -> {
            String hash = passwordService.hash("correct");
            assertFalse(passwordService.matches("wrong", hash));
            assertFalse(passwordService.matches("correct", "garbage"));
            assertFalse(passwordService.matches("correct", "1:@@@:###"));
            assertFalse(passwordService.matches(null, hash));
            return "异常输入不抛底层异常、不绕过校验";
        });
    }
}
