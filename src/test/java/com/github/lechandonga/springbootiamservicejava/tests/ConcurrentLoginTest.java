package com.github.lechandonga.springbootiamservicejava.tests;

import com.github.lechandonga.springbootiamservicejava.support.ApiClient;
import com.github.lechandonga.springbootiamservicejava.support.IamTestBase;
import com.github.lechandonga.springbootiamservicejava.support.Scenario;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景: 并发登录不能绕过失败锁定阈值
 * N 个线程同时用错误口令冲击一个账号，最终该账号必须进入锁定状态；
 * 之后即使口令正确，所有并发请求得到的也只能是 ACCOUNT_LOCKED。
 */
class ConcurrentLoginTest extends IamTestBase {

    @Test
    void concurrentFailedLoginsStillLockAccount() throws Exception {
        Scenario.begin("并发登录锁定",
                "20 个线程并发错误登录同一账号，失败计数串行化，账号必被锁定且不可绕过");

        String user = "concurrent_victim";
        createUser(user, "secret-pw", Set.of("viewer"), Map.of());

        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<String> codes = new ConcurrentLinkedQueue<>();

        Scenario.runCase("20 个线程并发发起错误口令登录", () -> {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        ApiClient.Response response = login(user, "bad-pw");
                        codes.add(response.code());
                    } catch (Exception e) {
                        codes.add("EXCEPTION:" + e.getClass().getSimpleName());
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            try {
                assertTrue(done.await(30, TimeUnit.SECONDS), "所有并发登录应在超时前完成");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            return "完成请求数=" + codes.size();
        });

        Scenario.runCase("并发结束后账号处于锁定状态", () -> {
            long badCredentials = codes.stream().filter("BAD_CREDENTIALS"::equals).count();
            long locked = codes.stream().filter("ACCOUNT_LOCKED"::equals).count();
            assertEquals(threads, badCredentials + locked,
                    "所有响应必须是 BAD_CREDENTIALS 或 ACCOUNT_LOCKED: " + codes);
            assertTrue(locked >= 1, "至少阈值之后的请求应看到 ACCOUNT_LOCKED: " + codes);
            // Exactly threshold-1 bad credentials can precede the first lock at minimum.
            assertTrue(badCredentials <= 5, "绕过阈值的成功计数过多: bad=" + badCredentials);
            return "BAD_CREDENTIALS=" + badCredentials + ", ACCOUNT_LOCKED=" + locked;
        });

        Scenario.runCase("锁定后即使口令正确也无法并发登录", () -> {
            int more = 8;
            CountDownLatch start2 = new CountDownLatch(1);
            CountDownLatch done2 = new CountDownLatch(more);
            AtomicInteger lockedCount = new AtomicInteger();
            for (int i = 0; i < more; i++) {
                pool.submit(() -> {
                    try {
                        start2.await();
                        if (login(user, "secret-pw").code().equals("ACCOUNT_LOCKED")) {
                            lockedCount.incrementAndGet();
                        }
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done2.countDown();
                    }
                });
            }
            start2.countDown();
            try {
                assertTrue(done2.await(30, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            assertEquals(more, lockedCount.get(), "锁定窗口内正确口令也必须全部被拒绝");
            pool.shutdownNow();
            return "8 个并发正确口令请求全部返回 ACCOUNT_LOCKED";
        });
    }
}
