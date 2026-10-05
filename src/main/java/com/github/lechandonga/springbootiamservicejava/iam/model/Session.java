package com.github.lechandonga.springbootiamservicejava.iam.model;

import java.time.Instant;

/** 登录会话，刷新令牌围绕同一会话形成可整体吊销的会话链。 */
public class Session {

    private final String id;
    private final String username;
    private final long accountSecurityVersion;
    private boolean revoked = false;
    private Instant revokedAt;
    private String revokeReason;
    private final Instant createdAt = Instant.now();

    public Session(String id, String username, long accountSecurityVersion) {
        this.id = id;
        this.username = username;
        this.accountSecurityVersion = accountSecurityVersion;
    }

    public String getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public long getAccountSecurityVersion() {
        return accountSecurityVersion;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void revoke(String reason) {
        this.revoked = true;
        this.revokedAt = Instant.now();
        this.revokeReason = reason;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public String getRevokeReason() {
        return revokeReason;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
