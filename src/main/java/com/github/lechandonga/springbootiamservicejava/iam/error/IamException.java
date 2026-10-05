package com.github.lechandonga.springbootiamservicejava.iam.error;

/** 业务异常，只携带稳定错误码，不携带底层堆栈信息。 */
public class IamException extends RuntimeException {

    private final ErrorCode errorCode;

    public IamException(ErrorCode errorCode) {
        super(errorCode.message());
        this.errorCode = errorCode;
    }

    public IamException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
