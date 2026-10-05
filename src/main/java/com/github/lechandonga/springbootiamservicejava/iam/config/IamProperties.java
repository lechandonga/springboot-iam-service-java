package com.github.lechandonga.springbootiamservicejava.iam.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "iam")
public class IamProperties {

    /** 连续登录失败多少次后锁定账号。 */
    private int maxFailedAttempts = 5;

    /** 账号锁定时长。 */
    private Duration lockDuration = Duration.ofMinutes(5);

    /** 访问令牌有效期。 */
    private Duration accessTokenTtl = Duration.ofMinutes(15);

    /** 刷新令牌有效期。 */
    private Duration refreshTokenTtl = Duration.ofDays(14);

    /** HMAC-SHA256 签名密钥（Base64 或 UTF-8 文本）。 */
    private String tokenSigningKey = "change-me-local-dev-hmac-sha256-secret-key";

    public int getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    public void setMaxFailedAttempts(int maxFailedAttempts) {
        this.maxFailedAttempts = maxFailedAttempts;
    }

    public Duration getLockDuration() {
        return lockDuration;
    }

    public void setLockDuration(Duration lockDuration) {
        this.lockDuration = lockDuration;
    }

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public void setAccessTokenTtl(Duration accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }

    public Duration getRefreshTokenTtl() {
        return refreshTokenTtl;
    }

    public void setRefreshTokenTtl(Duration refreshTokenTtl) {
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public String getTokenSigningKey() {
        return tokenSigningKey;
    }

    public void setTokenSigningKey(String tokenSigningKey) {
        this.tokenSigningKey = tokenSigningKey;
    }
}
