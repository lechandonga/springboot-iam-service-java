package com.github.lechandonga.springbootiamservicejava.iam.auth;

import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import com.github.lechandonga.springbootiamservicejava.iam.model.Account;
import com.github.lechandonga.springbootiamservicejava.iam.model.Effect;
import com.github.lechandonga.springbootiamservicejava.iam.model.Policy;
import com.github.lechandonga.springbootiamservicejava.iam.repo.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.iam.repo.PolicyRepository;
import com.github.lechandonga.springbootiamservicejava.iam.security.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;

@Service
public class AdminService {

    private final AccountRepository accounts;
    private final PolicyRepository policies;
    private final PasswordEncoder passwordEncoder;

    public AdminService(AccountRepository accounts, PolicyRepository policies,
                        PasswordEncoder passwordEncoder) {
        this.accounts = accounts;
        this.policies = policies;
        this.passwordEncoder = passwordEncoder;
    }

    public Account createAccount(String username, String rawPassword, List<String> roles,
                                 List<String> attributes, Boolean enabled) {
        if (username == null || username.isBlank() || rawPassword == null || rawPassword.length() < 6) {
            throw new IamException(ErrorCode.BAD_REQUEST, "用户名不能为空且口令至少 6 位");
        }
        Account account = new Account(username);
        account.setPasswordHash(passwordEncoder.encode(rawPassword));
        if (roles != null) {
            account.getRoles().addAll(roles);
            roles.forEach(r -> accounts.getOrCreateRole(r).getMembers().add(username));
        }
        if (attributes != null) {
            account.getAttributes().addAll(attributes);
        }
        if (enabled != null) {
            account.setEnabled(enabled);
        }
        if (!accounts.create(account)) {
            throw new IamException(ErrorCode.USERNAME_TAKEN);
        }
        return account;
    }

    /** 更新账号安全相关信息；任意调整都会提升安全版本，旧令牌立即失效。 */
    public Account updateAccount(String username, Boolean enabled, List<String> roles,
                                 List<String> attributes, String newPassword) {
        Account account = accounts.getRequired(username);
        synchronized (account) {
            boolean securityChanged = false;
            if (enabled != null) {
                account.setEnabled(enabled);
                securityChanged = true;
            }
            if (roles != null) {
                account.getRoles().clear();
                account.getRoles().addAll(new HashSet<>(roles));
                securityChanged = true;
            }
            if (attributes != null) {
                account.getAttributes().clear();
                account.getAttributes().addAll(new HashSet<>(attributes));
                securityChanged = true;
            }
            if (newPassword != null) {
                if (newPassword.length() < 6) {
                    throw new IamException(ErrorCode.BAD_REQUEST, "口令至少 6 位");
                }
                account.setPasswordHash(passwordEncoder.encode(newPassword));
                securityChanged = true;
            }
            if (securityChanged) {
                account.bumpSecurityVersion();
            }
        }
        return account;
    }

    /** 管理员手动解锁并清零失败计数。 */
    public void unlockAccount(String username) {
        Account account = accounts.getRequired(username);
        synchronized (account) {
            account.setLockedUntil(null);
            account.setFailedAttempts(0);
        }
    }

    public Policy createPolicy(String id, String action, String effect, List<String> roles,
                               List<String> requiredAttributes) {
        if (id == null || action == null || effect == null) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        Effect parsed;
        try {
            parsed = Effect.valueOf(effect.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IamException(ErrorCode.BAD_REQUEST, "effect 必须是 ALLOW 或 DENY");
        }
        if (policies.find(id).isPresent()) {
            throw new IamException(ErrorCode.USERNAME_TAKEN, "策略 id 已存在");
        }
        Policy policy = new Policy(id, action, parsed);
        if (roles != null) {
            policy.getRoles().addAll(roles);
        }
        if (requiredAttributes != null) {
            policy.getRequiredAttributes().addAll(requiredAttributes);
        }
        policies.save(policy);
        return policy;
    }
}
