package com.github.lechandonga.springbootiamservicejava.service;

import com.github.lechandonga.springbootiamservicejava.domain.Account;
import com.github.lechandonga.springbootiamservicejava.domain.Policy;
import com.github.lechandonga.springbootiamservicejava.repository.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.repository.PolicyRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Default-deny, least-privilege authorization engine. A decision considers:
 * <ul>
 *   <li>current account state (disabled accounts are always denied),</li>
 *   <li>the account's live role set (changes apply to already-issued sessions),</li>
 *   <li>the account's live attributes (e.g. department),</li>
 *   <li>ordered policies; the first match decides, no match means DENY.</li>
 * </ul>
 * Every decision is audited with the policy that produced it.
 */
@Service
public class AuthorizationService {

    public record Decision(boolean allowed, String detail) {}

    private final AccountRepository accountRepository;
    private final PolicyRepository policyRepository;
    private final AuditService auditService;

    public AuthorizationService(AccountRepository accountRepository,
                                PolicyRepository policyRepository,
                                AuditService auditService) {
        this.accountRepository = accountRepository;
        this.policyRepository = policyRepository;
        this.auditService = auditService;
    }

    /** Live authorization check for a request belonging to an existing session. */
    public Decision authorize(String username, String chainId, String resource, String action) {
        Account account = accountRepository.find(username).orElse(null);
        if (account == null) {
            return deny(username, chainId, resource, action, "reason=account_missing;policy=default-deny");
        }
        if (!account.isEnabled()) {
            return deny(username, chainId, resource, action, "reason=account_disabled;policy=default-deny");
        }

        List<Policy> policies = policyRepository.findAllOrderedByPriority();
        for (Policy policy : policies) {
            if (subjectMatches(policy, account)
                    && wildcardMatches(policy.getResource(), resource)
                    && wildcardMatches(policy.getAction(), action)) {
                String detail = "policy=" + policy.getId() + ";effect=" + policy.getEffect()
                        + ";subject=" + policy.getSubject();
                if (policy.getEffect() == Policy.Effect.ALLOW) {
                    auditService.record("AUTHZ", username, chainId, resource, action, "ALLOW", detail);
                    return new Decision(true, detail);
                }
                auditService.record("AUTHZ", username, chainId, resource, action, "DENY", detail);
                return new Decision(false, detail);
            }
        }
        return deny(username, chainId, resource, action,
                "reason=no_matching_policy;policy=default-deny");
    }

    private Decision deny(String username, String chainId, String resource, String action, String detail) {
        auditService.record("AUTHZ", username, chainId, resource, action, "DENY", detail);
        return new Decision(false, detail);
    }

    private boolean subjectMatches(Policy policy, Account account) {
        String subject = policy.getSubject();
        if ("*".equals(subject)) {
            return true;
        }
        if (subject.startsWith("role:")) {
            return account.getRoles().contains(subject.substring("role:".length()));
        }
        if (subject.startsWith("attr:")) {
            String condition = subject.substring("attr:".length());
            int eq = condition.indexOf('=');
            if (eq < 0) {
                return false;
            }
            String key = condition.substring(0, eq);
            String expected = condition.substring(eq + 1);
            return expected.equals(account.getAttributes().get(key));
        }
        if (subject.startsWith("user:")) {
            return subject.substring("user:".length()).equals(account.getUsername());
        }
        return false;
    }

    static boolean wildcardMatches(String pattern, String value) {
        if (pattern.equals(value)) {
            return true;
        }
        if (pattern.endsWith("*")) {
            return value.startsWith(pattern.substring(0, pattern.length() - 1));
        }
        return false;
    }
}
