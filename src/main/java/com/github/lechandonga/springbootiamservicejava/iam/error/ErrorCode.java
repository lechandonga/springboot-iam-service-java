package com.github.lechandonga.springbootiamservicejava.iam.error;

/** 对外暴露的稳定错误码，底层异常不会透传到接口。 */
public enum ErrorCode {

    INVALID_CREDENTIALS(401, "用户名或口令错误"),
    ACCOUNT_LOCKED(423, "账号已被临时锁定"),
    ACCOUNT_DISABLED(403, "账号已被禁用"),

    TOKEN_MISSING(401, "缺少访问令牌"),
    TOKEN_MALFORMED(401, "令牌格式不合法"),
    TOKEN_BAD_SIGNATURE(401, "令牌签名不合法"),
    TOKEN_TAMPERED(401, "令牌内容被篡改"),
    TOKEN_EXPIRED(401, "令牌已过期"),
    TOKEN_REVOKED(401, "令牌已被吊销"),

    ACCESS_DENIED(403, "默认拒绝：没有匹配的放行策略"),
    ACCOUNT_NOT_FOUND(404, "账号不存在"),
    POLICY_NOT_FOUND(404, "策略不存在"),
    USERNAME_TAKEN(409, "用户名已存在"),

    BAD_REQUEST(400, "请求参数不合法"),
    INTERNAL_ERROR(500, "服务内部错误");

    private final int httpStatus;
    private final String message;

    ErrorCode(int httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String message() {
        return message;
    }
}
