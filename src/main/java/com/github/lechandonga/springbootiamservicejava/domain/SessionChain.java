package com.github.lechandonga.springbootiamservicejava.domain;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * A login session chain. Each successful refresh rotates the refresh token
 * (one-time use) while the chain id stays stable. Reuse of an already
 * consumed refresh token revokes the whole chain.
 */
public class SessionChain {

    private final String chainId;
    private final String username;
    private String currentRefreshTokenHash;
    private boolean revoked;
    private String revokeReason;
    private final Instant createdAt;
    private final Set<String> consumedRefreshTokenHashes = new HashSet<>();

    public SessionChain(String chainId, String username, String currentRefreshTokenHash, Instant createdAt) {
        this.chainId = chainId;
        this.username = username;
        this.currentRefreshTokenHash = currentRefreshTokenHash;
        this.createdAt = createdAt;
    }

    public String getChainId() { return chainId; }
    public String getUsername() { return username; }

    public String getCurrentRefreshTokenHash() { return currentRefreshTokenHash; }
    public void setCurrentRefreshTokenHash(String currentRefreshTokenHash) {
        this.currentRefreshTokenHash = currentRefreshTokenHash;
    }

    public boolean isRevoked() { return revoked; }
    public String getRevokeReason() { return revokeReason; }

    public void revoke(String reason) {
        this.revoked = true;
        this.revokeReason = reason;
    }

    public Instant getCreatedAt() { return createdAt; }

    /** Records a refresh-token hash that was validly issued but is no longer current. */
    public void markConsumed(String tokenHash) {
        consumedRefreshTokenHashes.add(tokenHash);
    }

    public boolean wasConsumed(String tokenHash) {
        return consumedRefreshTokenHashes.contains(tokenHash);
    }
}
