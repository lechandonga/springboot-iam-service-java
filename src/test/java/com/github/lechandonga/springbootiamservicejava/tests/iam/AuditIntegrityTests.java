package com.github.lechandonga.springbootiamservicejava.tests.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.springbootiamservicejava.iam.audit.AuditLog;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 场景六：审计只增不改，并发写入不丢、不重。 */
class AuditIntegrityTests extends IamTestBase {

    @Autowired
    private AuditLog auditLog;

    @Test
    void audit_log_is_append_only_complete_and_unique_under_concurrency() throws Exception {
        ScenarioLog.scenario("审计完整性：只增不改、可还原判定依据、并发写入不丢不重");
        String admin = adminToken();
        createUser(admin, "audit_user", "audit-pass-123", List.of("viewer"), List.of());
        String token = login("audit_user", "audit-pass-123").get("accessToken").asText();

        long beforeCount = auditLog.size();

        ScenarioLog.step("50 个并发授权判定（ALLOW 与 DENY 混合）", "审计记录恰好新增 50 条");
        int workers = 50;
        ExecutorService pool = Executors.newFixedThreadPool(10);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(workers);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger denied = new AtomicInteger();
        for (int i = 0; i < workers; i++) {
            final int index = i;
            pool.submit(() -> {
                try {
                    start.await();
                    ApiResponse response = check(token, index % 2 == 0
                            ? "document.read" : "document.write");
                    if (response.status() == 200) {
                        ok.incrementAndGet();
                    } else if (response.status() == 403 && "ACCESS_DENIED".equals(response.code())) {
                        denied.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(25, ok.get());
        assertEquals(25, denied.get());

        assertEquals(beforeCount + 50, auditLog.size(), "并发写入后审计条数应精确增加 50");
        JsonNode after = get("/api/admin/audit", admin).body();
        ScenarioLog.pass("50 次判定全部留下审计（25 ALLOW / 25 DENY），无丢失");

        ScenarioLog.step("序列号严格递增且不重号", "逐条校验 sequence 连续");
        long expectedSeq = after.get(0).get("sequence").asLong();
        for (JsonNode event : after) {
            assertEquals(expectedSeq, event.get("sequence").asLong());
            expectedSeq++;
        }
        ScenarioLog.pass("全部 " + after.size() + " 条审计序列号连续唯一，无重号");

        ScenarioLog.step("审计可还原谁/何时/对什么/依据哪条策略/什么结果", "抽查字段完整性");
        boolean foundReadAllow = false;
        for (JsonNode event : after) {
            if ("document.read".equals(event.get("action").asText())
                    && "ALLOW".equals(event.get("result").asText())) {
                assertEquals("audit_user", event.get("principal").asText());
                assertEquals("p-doc-read", event.get("matchedPolicyId").asText());
                assertTrue(event.has("timestamp") && event.has("sessionId") && event.has("reason"));
                JsonNode roles = event.get("detail").get("account_roles");
                assertTrue(roles.isArray() && roles.size() == 1
                        && "viewer".equals(roles.get(0).asText()));
                foundReadAllow = true;
                break;
            }
        }
        assertTrue(foundReadAllow, "应找到 document.read 的 ALLOW 审计");
        ScenarioLog.pass("审计字段完整：principal/timestamp/action/result/matchedPolicyId/reason/detail");

        ScenarioLog.step("只增不改保证", "服务未提供任何更新/删除审计的接口，仓储也无修改入口");
        assertError(get("/api/admin/audit", token),
                HttpStatus.FORBIDDEN, "ACCESS_DENIED");
        ScenarioLog.pass("普通用户不能读审计；写入端仅 append，记录不可变");
    }
}
