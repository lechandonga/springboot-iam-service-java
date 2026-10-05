package com.github.lechandonga.springbootiamservicejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "iam")
public class IamProperties {

    private Duration accessTokenTtl = Duration.ofMinutes(10);
    private Duration refreshTokenTtl = Duration.ofHours(12);
    private int maxLoginFailures = 5;
    private Duration lockDuration = Duration.ofMinutes(15);
    private String tokenSigningSecret = "local-dev-only-change-me";
    private String auditLogFile = "target/audit/audit.log";

    public Duration getAccessTokenTtl() { return accessTokenTtl; }
    public void setAccessTokenTtl(Duration accessTokenTtl) { this.accessTokenTtl = accessTokenTtl; }

    public Duration getRefreshTokenTtl() { return refreshTokenTtl; }
    public void setRefreshTokenTtl(Duration refreshTokenTtl) { this.refreshTokenTtl = refreshTokenTtl; }

    public int getMaxLoginFailures() { return maxLoginFailures; }
    public void setMaxLoginFailures(int maxLoginFailures) { this.maxLoginFailures = maxLoginFailures; }

    public Duration getLockDuration() { return lockDuration; }
    public void setLockDuration(Duration lockDuration) { this.lockDuration = lockDuration; }

    public String getTokenSigningSecret() { return tokenSigningSecret; }
    public void setTokenSigningSecret(String tokenSigningSecret) { this.tokenSigningSecret = tokenSigningSecret; }

    public String getAuditLogFile() { return auditLogFile; }
    public void setAuditLogFile(String auditLogFile) { this.auditLogFile = auditLogFile; }
}
