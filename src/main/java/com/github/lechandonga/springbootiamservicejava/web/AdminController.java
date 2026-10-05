package com.github.lechandonga.springbootiamservicejava.web;

import com.github.lechandonga.springbootiamservicejava.domain.Account;
import com.github.lechandonga.springbootiamservicejava.domain.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.domain.IamException;
import com.github.lechandonga.springbootiamservicejava.domain.Policy;
import com.github.lechandonga.springbootiamservicejava.repository.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.repository.PolicyRepository;
import com.github.lechandonga.springbootiamservicejava.repository.SessionRepository;
import com.github.lechandonga.springbootiamservicejava.service.AuditService;
import com.github.lechandonga.springbootiamservicejava.service.AuthorizationService;
import com.github.lechandonga.springbootiamservicejava.service.PasswordService;
import com.github.lechandonga.springbootiamservicejava.web.dto.Requests;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Administrative endpoints. Every call passes through the same default-deny
 * engine (resource="admin:..."); they are not hard-coded open.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AccountRepository accountRepository;
    private final PolicyRepository policyRepository;
    private final SessionRepository sessionRepository;
    private final PasswordService passwordService;
    private final AuthorizationService authorizationService;
    private final AuditService auditService;

    public AdminController(AccountRepository accountRepository, PolicyRepository policyRepository,
                           SessionRepository sessionRepository, PasswordService passwordService,
                           AuthorizationService authorizationService, AuditService auditService) {
        this.accountRepository = accountRepository;
        this.policyRepository = policyRepository;
        this.sessionRepository = sessionRepository;
        this.passwordService = passwordService;
        this.authorizationService = authorizationService;
        this.auditService = auditService;
    }

    @PostMapping("/accounts")
    public Map<String, Object> createAccount(@RequestBody Requests.CreateAccountRequest body,
                                             HttpServletRequest request) {
        guard(request, "admin:account", "create");
        if (isBlank(body.username()) || isBlank(body.password())) {
            throw new IamException(ErrorCode.VALIDATION_ERROR, "username and password are required");
        }
        if (accountRepository.exists(body.username())) {
            throw new IamException(ErrorCode.CONFLICT, "account already exists");
        }
        Account account = new Account(body.username(), passwordService.hash(body.password()));
        if (body.roles() != null) {
            account.getRoles().addAll(body.roles());
        }
        if (body.attributes() != null) {
            account.getAttributes().putAll(body.attributes());
        }
        accountRepository.save(account);
        auditService.record("ADMIN", principal(request), null, "admin:account", "create", "ALLOW",
                "target=" + body.username());
        return accountView(account);
    }

    @GetMapping("/accounts")
    public List<Map<String, Object>> listAccounts(HttpServletRequest request) {
        guard(request, "admin:account", "read");
        return accountRepository.findAll().stream().map(this::accountView).toList();
    }

    @PutMapping("/accounts/{username}/enabled")
    public Map<String, Object> setEnabled(@PathVariable String username,
                                          @RequestBody Requests.StatusRequest body,
                                          HttpServletRequest request) {
        guard(request, "admin:account", "update");
        Account account = requireAccount(username);
        account.setEnabled(body.enabled());
        if (!body.enabled()) {
            // Disabling immediately invalidates every session chain of the account.
            sessionRepository.revokeAllFor(username, "account_disabled_by_admin");
        } else {
            // Explicit re-enable is an administrator action: clear lock state.
            account.setLockedUntil(null);
            account.setFailedLoginCount(0);
        }
        auditService.record("ADMIN", principal(request), null, "admin:account", "update", "ALLOW",
                "target=" + username + ";enabled=" + body.enabled());
        return accountView(account);
    }

    @PutMapping("/accounts/{username}/roles")
    public Map<String, Object> setRoles(@PathVariable String username,
                                        @RequestBody Requests.RolesRequest body,
                                        HttpServletRequest request) {
        guard(request, "admin:account", "update");
        Account account = requireAccount(username);
        account.getRoles().clear();
        if (body.roles() != null) {
            account.getRoles().addAll(body.roles());
        }
        // Role changes are live: authorization re-reads the account on each request.
        auditService.record("ADMIN", principal(request), null, "admin:account", "update", "ALLOW",
                "target=" + username + ";roles=" + account.getRoles());
        return accountView(account);
    }

    @PutMapping("/accounts/{username}/attributes")
    public Map<String, Object> setAttributes(@PathVariable String username,
                                             @RequestBody Requests.AttributesRequest body,
                                             HttpServletRequest request) {
        guard(request, "admin:account", "update");
        Account account = requireAccount(username);
        account.getAttributes().clear();
        if (body.attributes() != null) {
            account.getAttributes().putAll(body.attributes());
        }
        auditService.record("ADMIN", principal(request), null, "admin:account", "update", "ALLOW",
                "target=" + username + ";attributes=" + account.getAttributes());
        return accountView(account);
    }

    @PutMapping("/accounts/{username}/password")
    public Map<String, Object> resetPassword(@PathVariable String username,
                                             @RequestBody Requests.PasswordChangeRequest body,
                                             HttpServletRequest request) {
        guard(request, "admin:account", "update");
        if (isBlank(body.newPassword())) {
            throw new IamException(ErrorCode.VALIDATION_ERROR, "newPassword is required");
        }
        Account account = requireAccount(username);
        account.setPasswordHash(passwordService.hash(body.newPassword()));
        sessionRepository.revokeAllFor(username, "password_reset_by_admin");
        auditService.record("ADMIN", principal(request), null, "admin:account", "update", "ALLOW",
                "target=" + username + ";sessions_revoked=true");
        return Map.of("username", username, "result", "password_updated");
    }

    @GetMapping("/sessions/{username}")
    public List<Map<String, Object>> sessions(@PathVariable String username, HttpServletRequest request) {
        guard(request, "admin:session", "read");
        return sessionRepository.findByUsername(username).stream()
                .map(c -> Map.<String, Object>of(
                        "chainId", c.getChainId(),
                        "revoked", c.isRevoked(),
                        "revokeReason", String.valueOf(c.getRevokeReason()),
                        "createdAt", c.getCreatedAt()))
                .toList();
    }

    @PostMapping("/policies")
    public Map<String, Object> upsertPolicy(@RequestBody Requests.PolicyRequest body,
                                            HttpServletRequest request) {
        guard(request, "admin:policy", "manage");
        if (isBlank(body.id()) || isBlank(body.subject()) || isBlank(body.resource())
                || isBlank(body.action()) || isBlank(body.effect())) {
            throw new IamException(ErrorCode.VALIDATION_ERROR,
                    "id, subject, resource, action and effect are required");
        }
        Policy.Effect effect;
        try {
            effect = Policy.Effect.valueOf(body.effect().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IamException(ErrorCode.VALIDATION_ERROR, "effect must be ALLOW or DENY");
        }
        Policy policy = new Policy(body.id(), body.subject(), body.resource(), body.action(),
                effect, body.priority());
        policyRepository.save(policy);
        auditService.record("ADMIN", principal(request), null, "admin:policy", "manage", "ALLOW",
                "policy=" + body.id());
        return policyView(policy);
    }

    @GetMapping("/policies")
    public List<Map<String, Object>> listPolicies(HttpServletRequest request) {
        guard(request, "admin:policy", "read");
        return policyRepository.findAllOrderedByPriority().stream().map(this::policyView).toList();
    }

    @DeleteMapping("/policies/{id}")
    public Map<String, Object> deletePolicy(@PathVariable String id, HttpServletRequest request) {
        guard(request, "admin:policy", "manage");
        boolean removed = policyRepository.delete(id);
        if (!removed) {
            throw new IamException(ErrorCode.NOT_FOUND, "policy does not exist");
        }
        auditService.record("ADMIN", principal(request), null, "admin:policy", "manage", "ALLOW",
                "policy=" + id + ";deleted=true");
        return Map.of("id", id, "result", "deleted");
    }

    @GetMapping("/audit")
    public List<?> audit(HttpServletRequest request) {
        guard(request, "admin:audit", "read");
        return auditService.allRecords();
    }

    private void guard(HttpServletRequest request, String resource, String action) {
        String username = (String) request.getAttribute("iam.username");
        String chainId = (String) request.getAttribute("iam.chainId");
        AuthorizationService.Decision decision = authorizationService.authorize(
                username, chainId, resource, action);
        if (!decision.allowed()) {
            throw new IamException(ErrorCode.ACCESS_DENIED, decision.detail());
        }
    }

    private Account requireAccount(String username) {
        return accountRepository.find(username)
                .orElseThrow(() -> new IamException(ErrorCode.NOT_FOUND, "account does not exist"));
    }

    private static String principal(HttpServletRequest request) {
        return (String) request.getAttribute("iam.username");
    }

    private Map<String, Object> accountView(Account account) {
        return Map.of(
                "username", account.getUsername(),
                "enabled", account.isEnabled(),
                "roles", Set.copyOf(account.getRoles()),
                "attributes", Map.copyOf(account.getAttributes()),
                "failedLoginCount", account.getFailedLoginCount(),
                "lockedUntil", String.valueOf(account.getLockedUntil()));
    }

    private Map<String, Object> policyView(Policy policy) {
        return Map.of(
                "id", policy.getId(),
                "subject", policy.getSubject(),
                "resource", policy.getResource(),
                "action", policy.getAction(),
                "effect", policy.getEffect().name(),
                "priority", policy.getPriority());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
