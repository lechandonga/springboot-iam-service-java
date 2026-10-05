package com.github.lechandonga.springbootiamservicejava.domain;

/**
 * Business-level exception carrying a stable {@link ErrorCode}. Lower-level
 * exceptions are translated to ErrorCode.INTERNAL_ERROR by the web layer.
 */
public class IamException extends RuntimeException {

    private final ErrorCode errorCode;

    public IamException(ErrorCode errorCode) {
        super(errorCode.safeMessage());
        this.errorCode = errorCode;
    }

    public IamException(ErrorCode errorCode, String safeDetail) {
        super(safeDetail);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
