package com.github.lechandonga.springbootiamservicejava.iam.authz;

import com.github.lechandonga.springbootiamservicejava.iam.audit.AuditLog;
import com.github.lechandonga.springbootiamservicejava.iam.model.Account;
import com.github.lechandonga.springbootiamservicejava.iam.model.Effect;
import com.github.lechandonga.springbootiamservicejava.iam.model.Policy;
import com.github.lechandonga.springbootiamservicejava.iam.repo.PolicyRepository;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * 最小权限授权引擎：默认拒绝。
 * 策略命中条件：操作匹配（支持末尾 * 通配）、账号拥有策略要求的任一角色、
 * 且拥有策略要求的全部账号属性。命中的 DENY 优先于 ALLOW。
 */
@Service
public class AuthorizationService {

    private final PolicyRepository policies;
    private final AuditLog auditLog;

    public AuthorizationService(PolicyRepository policies, AuditLog auditLog) {
        this.policies = policies;
        this.auditLog = auditLog;
    }

    public Decision evaluate(Account account, String action) {
        Set<String> roles = account.getRoles();
        Set<String> attributes = account.getAttributes();
        Policy allowHit = null;

        for (Policy policy : policies.all()) {
            if (!actionMatches(policy.getAction(), action)) {
                continue;
            }
            if (!policy.getRoles().isEmpty() && policy.getRoles().stream().noneMatch(roles::contains)) {
                continue;
            }
            if (!attributes.containsAll(policy.getRequiredAttributes())) {
                continue;
            }
            if (policy.getEffect() == Effect.DENY) {
                return Decision.explicitDeny(policy.getId());
            }
            if (allowHit == null) {
                allowHit = policy;
            }
        }
        if (allowHit != null) {
            return Decision.allow(allowHit.getId());
        }
        return Decision.defaultDeny("no_matching_policy_default_deny");
    }

    /** 执行授权判定并写审计：每次放行与拒绝都只增记录一条。 */
    public Decision enforce(Account account, String sessionId, String action, Map<String, Object> extra) {
        Decision decision = evaluate(account, action);
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("account_roles", account.getRoles().stream().sorted().toList());
        detail.put("account_attributes", account.getAttributes().stream().sorted().toList());
        if (extra != null) {
            detail.putAll(extra);
        }
        auditLog.append(
                account.getUsername(),
                sessionId,
                action,
                decision.allowed() ? "ALLOW" : "DENY",
                decision.matchedPolicyId(),
                decision.reason(),
                detail);
        return decision;
    }

    static boolean actionMatches(String pattern, String action) {
        if (pattern.equals(action)) {
            return true;
        }
        if (pattern.endsWith("*")) {
            return action.startsWith(pattern.substring(0, pattern.length() - 1));
        }
        return false;
    }
}
