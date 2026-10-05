package com.github.lechandonga.springbootiamservicejava.domain;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Local user account. The password is stored only as a salted PBKDF2 hash
 * (iterations:saltBase64:hashBase64); plaintext passwords are never retained.
 */
public class Account {

    private final String username;
    private String passwordHash;
    private boolean enabled = true;
    private final Set<String> roles = new HashSet<>();
    private final Map<String, String> attributes = new HashMap<>();
    private int failedLoginCount;
    private Instant lockedUntil;

    public Account(String username, String passwordHash) {
        this.username = username;
        this.passwordHash = passwordHash;
    }

    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public Set<String> getRoles() { return roles; }
    public Map<String, String> getAttributes() { return attributes; }

    public int getFailedLoginCount() { return failedLoginCount; }
    public void setFailedLoginCount(int failedLoginCount) { this.failedLoginCount = failedLoginCount; }

    public Instant getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(Instant lockedUntil) { this.lockedUntil = lockedUntil; }
}
