package com.github.lechandonga.springbootiamservicejava.iam.model;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/** 本地账号。口令以 PBKDF2 加盐哈希保存，永不保存明文。 */
public class Account {

    private final String username;
    private String passwordSalt;
    private String passwordHash;
    private final Set<String> roles = new HashSet<>();
    private final Set<String> attributes = new HashSet<>();
    private boolean enabled = true;

    /** 安全版本号：禁用、口令变更、角色/属性调整都会 +1，已签发令牌立即失效。 */
    private long securityVersion = 0;
    private int failedAttempts = 0;
    private Instant lockedUntil;
    private final Instant createdAt = Instant.now();

    public Account(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordSalt() {
        return passwordSalt;
    }

    public void setPasswordSalt(String passwordSalt) {
        this.passwordSalt = passwordSalt;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        this.securityVersion++;
    }

    public long getSecurityVersion() {
        return securityVersion;
    }

    /** 权限/角色/属性调整后调用，使旧会话立即按新状态生效。 */
    public void bumpSecurityVersion() {
        this.securityVersion++;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
