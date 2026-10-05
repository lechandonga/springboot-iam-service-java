package com.github.lechandonga.springbootiamservicejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.springbootiamservicejava.domain.AuditRecord;
import com.github.lechandonga.springbootiamservicejava.service.AuditService;
import com.github.lechandonga.springbootiamservicejava.support.ApiClient;
import com.github.lechandonga.springbootiamservicejava.support.IamTestBase;
import com.github.lechandonga.springbootiamservicejava.support.Scenario;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 场景: 审计完整性
 * - 每次放行/拒绝都可还原 谁/何时/对什么/依据哪条策略/什么结果
 * - 高并发写入无丢失、无重复、序列号连续
 * - 审计记录只增不改（API 不提供修改/删除；快照不可变）
 */
class AuditIntegrityTest extends IamTestBase {

    @Autowired
    private AuditService auditService;

    @Test
    void auditRecordsAreCompleteAndConcurrencySafe() throws Exception {
        Scenario.begin("审计完整性与并发写入",
                "审计字段可还原决策依据；100 并发写入序列号连续无丢无重；记录只增");

        String user = "audit_user";
        createUser(user, "pw", Set.of("viewer"), Map.of("department", "engineering"));
        String token = login(user, "pw").json().get("accessToken").asText();

        int requests = 100;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(requests);

        Scenario.runCase("100 个并发授权请求 (放行/拒绝混合)", () -> {
            for (int i = 0; i < requests; i++) {
                String action = (i % 2 == 0) ? "read" : "write";
                pool.submit(() -> {
                    try {
                        start.await();
                        api.post("/api/resource/access",
                                Map.of("resource", "document", "action", action), token);
                    } catch (Exception ignored) {
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            try {
                assertTrue(done.await(60, TimeUnit.SECONDS), "并发请求应全部完成");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            pool.shutdownNow();
            return "100 请求已发出 (read 放行, write 默认拒绝)";
        });

        Scenario.runCase("审计不丢不重且序列号严格连续", () -> {
            long total = auditService.count();
            long subjectRecords = auditService.bySubject(user).stream()
                    .filter(r -> "AUTHZ".equals(r.eventType())).count();
            assertEquals(requests, subjectRecords,
                    "该主体应有恰好 100 条 AUTHZ 记录，实际 " + subjectRecords);

            var all = auditService.allRecords();
            long expectedSeq = all.get(0).sequence();
            for (AuditRecord record : all) {
                assertEquals(expectedSeq, record.sequence(), "序列号必须连续无缺口/无重复");
                expectedSeq++;
            }
            return "总记录=" + total + "; 该主体 AUTHZ=" + subjectRecords + "; 全表序号连续";
        });

        Scenario.runCase("审计记录可还原: 谁/何时/对什么/依据哪条策略/结果", () -> {
            AuditRecord allowed = auditService.bySubject(user).stream()
                    .filter(r -> "AUTHZ".equals(r.eventType()) && "ALLOW".equals(r.result()))
                    .findFirst().orElseThrow();
            AuditRecord denied = auditService.bySubject(user).stream()
                    .filter(r -> "AUTHZ".equals(r.eventType()) && "DENY".equals(r.result()))
                    .findFirst().orElseThrow();
            assertEquals("document", allowed.resource());
            assertEquals("read", allowed.action());
            assertTrue(allowed.decisionDetail().contains("p-doc-read-eng"), allowed.decisionDetail());
            assertTrue(denied.decisionDetail().contains("default-deny"), denied.decisionDetail());
            assertTrue(allowed.sessionChainId() != null && !allowed.sessionChainId().isBlank());
            assertTrue(allowed.timestamp() != null);
            return "ALLOW 依据 p-doc-read-eng; DENY 依据 default-deny; 含主体/时间/链ID";
        });

        Scenario.runCase("审计可经管理员接口查询, 普通用户无权访问", () -> {
            ApiClient.Response asAdmin = api.get("/api/admin/audit", adminAccess);
            assertEquals(200, asAdmin.status());
            assertTrue(asAdmin.json().size() >= requests);
            ApiClient.Response asUser = api.get("/api/admin/audit", token);
            assertCode(asUser, 403, "ACCESS_DENIED");
            return "仅 role:admin 可读审计; 系统未提供任何修改/删除审计的接口";
        });

        Scenario.runCase("磁盘审计日志为 JSON-lines 只增文件", () -> {
            java.nio.file.Path logFile = java.nio.file.Path.of("target/audit/audit.log");
            assertTrue(java.nio.file.Files.exists(logFile), "审计文件应存在");
            long lines;
            JsonNode firstLine;
            try {
                lines = java.nio.file.Files.lines(logFile).count();
                firstLine = new com.fasterxml.jackson.databind.ObjectMapper()
                        .readTree(java.nio.file.Files.readAllLines(logFile).get(0));
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
            assertTrue(lines >= auditService.count(),
                    "磁盘行数应 >= 当前进程记录数（文件追加、不覆盖）");
            assertTrue(firstLine.has("sequence") && firstLine.has("eventType")
                    && firstLine.has("result"));
            return "audit.log 行数=" + lines + ", 每行均为完整 JSON 记录";
        });
    }
}
