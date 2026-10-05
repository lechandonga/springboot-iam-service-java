package com.github.lechandonga.springbootiamservicejava.domain;

/**
 * Stable, externally visible error codes. Internal exception details are never
 * leaked through the API; only these codes plus a short safe message are.
 */
public enum ErrorCode {
    BAD_CREDENTIALS("username or password is incorrect"),
    ACCOUNT_LOCKED("account is temporarily locked due to repeated failed logins"),
    ACCOUNT_DISABLED("account is disabled"),
    MISSING_TOKEN("authentication token is required"),
    MALFORMED_TOKEN("token is malformed"),
    BAD_SIGNATURE("token signature is invalid or the payload was tampered with"),
    TOKEN_EXPIRED("token has expired"),
    TOKEN_REVOKED("token has been revoked"),
    TOKEN_TYPE_MISMATCH("wrong token type for this operation"),
    REFRESH_REPLAY("refresh token was already used; the whole session chain has been revoked"),
    ACCESS_DENIED("not permitted to perform this operation"),
    VALIDATION_ERROR("request payload is invalid"),
    NOT_FOUND("resource does not exist"),
    CONFLICT("resource already exists or state conflict"),
    INTERNAL_ERROR("internal error");

    private final String safeMessage;

    ErrorCode(String safeMessage) {
        this.safeMessage = safeMessage;
    }

    public String safeMessage() {
        return safeMessage;
    }
}
