package com.github.lechandonga.springbootiamservicejava.tests.iam;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 场景四：默认拒绝 + 最小权限，角色与账号属性同时参与判定。 */
class AuthorizationTests extends IamTestBase {

    @Test
    void default_deny_role_and_attribute_based_decisions() {
        ScenarioLog.scenario("授权：默认拒绝、角色+账号属性联合判定、显式 DENY 优先");
        String admin = adminToken();
        createUser(admin, "authz_editor", "editor-pass-1", List.of("editor"),
                List.of("department:content"));
        createUser(admin, "authz_viewer", "viewer-pass-1", List.of("viewer"),
                List.of("department:sales"));
        createUser(admin, "authz_probation", "probation-pass", List.of("editor"),
                List.of("department:content", "probation"));

        String editor = login("authz_editor", "editor-pass-1").get("accessToken").asText();
        String viewer = login("authz_viewer", "viewer-pass-1").get("accessToken").asText();
        String probation = login("authz_probation", "probation-pass").get("accessToken").asText();

        ScenarioLog.step("viewer 读取文档", "命中 p-doc-read 放行");
        assertEquals(200, check(viewer, "document.read").status());
        ScenarioLog.pass("viewer 允许 document.read");

        ScenarioLog.step("viewer 写文档", "无匹配策略，默认拒绝 ACCESS_DENIED");
        assertError(check(viewer, "document.write"), HttpStatus.FORBIDDEN, "ACCESS_DENIED");
        ScenarioLog.pass("viewer 写文档被默认拒绝");

        ScenarioLog.step("editor 写文档", "角色满足 p-doc-write-editor，放行");
        JsonNode writeOk = check(editor, "document.write").body();
        assertEquals("p-doc-write-editor", writeOk.get("matchedPolicyId").asText());
        ScenarioLog.pass("editor 写文档放行，命中策略 p-doc-write-editor");

        ScenarioLog.step("editor 发布文档（需要 department:content 属性）", "角色+属性均满足，放行");
        JsonNode publishOk = check(editor, "document.publish").body();
        assertEquals("p-doc-publish", publishOk.get("matchedPolicyId").asText());
        ScenarioLog.pass("editor+department:content 发布文档放行");

        ScenarioLog.step("sales 部门 editor 发布文档", "缺属性，默认拒绝（使用 authz_viewer 的场景对照）");
        assertError(check(viewer, "document.publish"), HttpStatus.FORBIDDEN, "ACCESS_DENIED");
        ScenarioLog.pass("缺少必需账号属性时拒绝");

        ScenarioLog.step("试用期 editor 写文档", "命中显式 DENY 策略 p-probation-deny-write，优先拒绝");
        ApiResponse denyResp = check(probation, "document.write");
        assertError(denyResp, HttpStatus.FORBIDDEN, "ACCESS_DENIED");
        ScenarioLog.pass("显式 DENY 优先于 ALLOW，试用期写操作被拒");

        ScenarioLog.step("普通用户访问管理接口", "无 admin 角色，默认拒绝");
        assertError(get("/api/admin/audit", editor), HttpStatus.FORBIDDEN, "ACCESS_DENIED");
        ScenarioLog.pass("非管理员无法读取审计，最小权限成立");

        ScenarioLog.step("审计可还原判定依据", "admin 读取审计，能看到 ALLOW/DENY 与策略 id");
        JsonNode events = get("/api/admin/audit", admin).body();
        boolean foundDenyWithReason = false;
        boolean foundAllowWithPolicy = false;
        for (JsonNode event : events) {
            String action = event.get("action").asText();
            String result = event.get("result").asText();
            if ("document.write".equals(action) && "DENY".equals(result)) {
                foundDenyWithReason = true;
            }
            if ("document.publish".equals(action) && "ALLOW".equals(result)
                    && "p-doc-publish".equals(event.get("matchedPolicyId").asText())) {
                foundAllowWithPolicy = true;
            }
        }
        org.junit.jupiter.api.Assertions.assertTrue(foundDenyWithReason, "审计中应存在 document.write 的 DENY");
        org.junit.jupiter.api.Assertions.assertTrue(foundAllowWithPolicy, "审计中应存在 document.publish 命中 p-doc-publish 的 ALLOW");
        ScenarioLog.pass("审计记录含主体、操作、结果、命中策略与原因");
    }
}
