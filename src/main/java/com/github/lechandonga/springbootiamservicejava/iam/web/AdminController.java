package com.github.lechandonga.springbootiamservicejava.iam.web;

import com.github.lechandonga.springbootiamservicejava.iam.audit.AuditLog;
import com.github.lechandonga.springbootiamservicejava.iam.auth.AdminService;
import com.github.lechandonga.springbootiamservicejava.iam.authz.AuthorizationService;
import com.github.lechandonga.springbootiamservicejava.iam.authz.Decision;
import com.github.lechandonga.springbootiamservicejava.iam.dto.Requests;
import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import com.github.lechandonga.springbootiamservicejava.iam.model.Account;
import com.github.lechandonga.springbootiamservicejava.iam.model.AuditEvent;
import com.github.lechandonga.springbootiamservicejava.iam.model.Policy;
import com.github.lechandonga.springbootiamservicejava.iam.security.CurrentPrincipal;
import com.github.lechandonga.springbootiamservicejava.iam.security.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;
    private final AuthorizationService authorizationService;
    private final AuditLog auditLog;

    public AdminController(AdminService adminService, AuthorizationService authorizationService,
                           AuditLog auditLog) {
        this.adminService = adminService;
        this.authorizationService = authorizationService;
        this.auditLog = auditLog;
    }

    @PostMapping("/accounts")
    public Map<String, Object> createAccount(@RequestBody Requests.CreateAccountRequest request) {
        authorize("iam.admin.account.create");
        if (request == null) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        Account account = adminService.createAccount(request.username(), request.password(),
                request.roles(), request.attributes(), request.enabled());
        return accountView(account);
    }

    @PostMapping("/accounts/{username}")
    public Map<String, Object> updateAccount(@PathVariable String username,
                                             @RequestBody Requests.UpdateAccountRequest request) {
        authorize("iam.admin.account.update");
        if (request == null) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        Account account = adminService.updateAccount(username, request.enabled(), request.roles(),
                request.attributes(), request.password());
        return accountView(account);
    }

    @PostMapping("/accounts/{username}/unlock")
    public Map<String, Object> unlock(@PathVariable String username) {
        authorize("iam.admin.account.unlock");
        adminService.unlockAccount(username);
        return Map.of("username", username, "locked", false);
    }

    @PostMapping("/policies")
    public Map<String, Object> createPolicy(@RequestBody Requests.PolicyRequest request) {
        authorize("iam.admin.policy.create");
        if (request == null) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        Policy policy = adminService.createPolicy(request.id(), request.action(), request.effect(),
                request.roles(), request.requiredAttributes());
        return Map.of(
                "id", policy.getId(),
                "action", policy.getAction(),
                "effect", policy.getEffect().name(),
                "roles", policy.getRoles().stream().sorted().toList(),
                "requiredAttributes", policy.getRequiredAttributes().stream().sorted().toList());
    }

    @GetMapping("/audit")
    public List<Map<String, Object>> auditEvents() {
        authorize("iam.admin.audit.read");
        return auditLog.all().stream().map(this::auditView).toList();
    }

    private void authorize(String action) {
        CurrentPrincipal principal = SecurityContext.required();
        Decision decision = authorizationService.enforce(
                principal.account(), principal.sessionId(), action, Map.of("via", "admin_api"));
        if (!decision.allowed()) {
            throw new IamException(ErrorCode.ACCESS_DENIED, decision.reason());
        }
    }

    private Map<String, Object> accountView(Account account) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("username", account.getUsername());
        view.put("enabled", account.isEnabled());
        view.put("roles", account.getRoles().stream().sorted().toList());
        view.put("attributes", account.getAttributes().stream().sorted().toList());
        view.put("securityVersion", account.getSecurityVersion());
        view.put("lockedUntil", account.getLockedUntil() == null ? null : account.getLockedUntil().toString());
        return view;
    }

    private Map<String, Object> auditView(AuditEvent event) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("sequence", event.getSequence());
        view.put("timestamp", event.getTimestamp().toString());
        view.put("principal", event.getPrincipal());
        view.put("sessionId", event.getSessionId());
        view.put("action", event.getAction());
        view.put("result", event.getResult());
        view.put("matchedPolicyId", event.getMatchedPolicyId());
        view.put("reason", event.getReason());
        view.put("detail", event.getDetail());
        return view;
    }
}
