package com.github.lechandonga.springbootiamservicejava.iam.model;

import java.time.Instant;

/** 一次性刷新令牌的服务端记录，令牌明文只在签发时返回，库里仅存哈希。 */
public class RefreshTokenRecord {

    private final String tokenHash;
    private final String sessionId;
    private final String username;
    private final Instant expiresAt;
    private boolean used = false;
    private Instant usedAt;

    public RefreshTokenRecord(String tokenHash, String sessionId, String username, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.sessionId = sessionId;
        this.username = username;
        this.expiresAt = expiresAt;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getUsername() {
        return username;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isUsed() {
        return used;
    }

    public void markUsed() {
        this.used = true;
        this.usedAt = Instant.now();
    }

    public Instant getUsedAt() {
        return usedAt;
    }
}
