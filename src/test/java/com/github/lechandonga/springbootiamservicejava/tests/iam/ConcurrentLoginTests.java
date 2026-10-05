package com.github.lechandonga.springbootiamservicejava.tests.iam;

import com.github.lechandonga.springbootiamservicejava.iam.auth.AuthService;
import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 场景二：并发登录不能绕过失败阈值。 */
class ConcurrentLoginTests extends IamTestBase {

    @Autowired
    private AuthService authService;

    @Test
    void concurrent_failed_logins_cannot_bypass_lock_threshold() throws Exception {
        ScenarioLog.scenario("并发登录：20 个错误口令并发提交，阈值不被并发摊薄");
        String admin = adminToken();
        createUser(admin, "concurrent_user", "correct-pass-1", List.of("viewer"), List.of());

        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger invalidCreds = new AtomicInteger();
        ConcurrentLinkedQueue<String> unexpected = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    try {
                        authService.login("concurrent_user",
                                "wrong-pass-" + Thread.currentThread().getId());
                        unexpected.add("错误口令竟然登录成功");
                    } catch (IamException e) {
                        if (e.errorCode() == ErrorCode.INVALID_CREDENTIALS) {
                            invalidCreds.incrementAndGet();
                        } else if (e.errorCode() != ErrorCode.ACCOUNT_LOCKED) {
                            unexpected.add("意外错误码: " + e.errorCode());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "并发登录应在超时前全部结束");
        pool.shutdown();

        ScenarioLog.step("20 个并发错误登录", "恰好 5 次计为 INVALID_CREDENTIALS，其余被锁拦截，无人成功");
        assertEquals(5, invalidCreds.get(), "只有阈值内的 5 次失败计入凭证错误，其余应直接看到锁定");
        assertTrue(unexpected.isEmpty(), "不应出现成功登录或其他错误: " + unexpected);
        ScenarioLog.pass("失败计数为 " + invalidCreds.get() + "，并发没有绕过阈值");

        ScenarioLog.step("锁定后并发使用正确口令", "全部得到 ACCOUNT_LOCKED");
        int attempts = 8;
        CountDownLatch start2 = new CountDownLatch(1);
        CountDownLatch done2 = new CountDownLatch(attempts);
        AtomicInteger locked = new AtomicInteger();
        ExecutorService pool2 = Executors.newFixedThreadPool(attempts);
        for (int i = 0; i < attempts; i++) {
            pool2.submit(() -> {
                try {
                    start2.await();
                    try {
                        authService.login("concurrent_user", "correct-pass-1");
                        unexpected.add("锁定期间不应登录成功");
                    } catch (IamException e) {
                        if (e.errorCode() == ErrorCode.ACCOUNT_LOCKED) {
                            locked.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done2.countDown();
                }
            });
        }
        start2.countDown();
        assertTrue(done2.await(30, TimeUnit.SECONDS));
        pool2.shutdown();
        assertEquals(attempts, locked.get());
        assertTrue(unexpected.isEmpty());
        ScenarioLog.pass("锁定状态下 " + locked.get() + " 个并发正确口令全部被拒为 ACCOUNT_LOCKED");
    }
}
