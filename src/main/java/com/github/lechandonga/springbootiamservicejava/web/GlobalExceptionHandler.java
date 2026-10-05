package com.github.lechandonga.springbootiamservicejava.web;

import com.github.lechandonga.springbootiamservicejava.domain.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.domain.IamException;
import com.github.lechandonga.springbootiamservicejava.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Translates every failure into a stable error-code JSON body. Low-level
 * exceptions are logged server-side but reported only as INTERNAL_ERROR,
 * so stack traces and implementation details never reach API callers.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(IamException.class)
    public ResponseEntity<Map<String, String>> handleBusiness(IamException e) {
        return ResponseEntity.status(statusFor(e.getErrorCode()))
                .body(Map.of("code", e.getErrorCode().name(), "message", e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleUnreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest()
                .body(Map.of("code", ErrorCode.VALIDATION_ERROR.name(),
                        "message", ErrorCode.VALIDATION_ERROR.safeMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleUnexpected(Exception e) {
        log.error("unexpected internal error", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("code", ErrorCode.INTERNAL_ERROR.name(),
                        "message", ErrorCode.INTERNAL_ERROR.safeMessage()));
    }

    private HttpStatus statusFor(ErrorCode code) {
        return switch (code) {
            case BAD_CREDENTIALS, MISSING_TOKEN, MALFORMED_TOKEN, BAD_SIGNATURE,
                 TOKEN_EXPIRED, TOKEN_REVOKED, TOKEN_TYPE_MISMATCH -> HttpStatus.UNAUTHORIZED;
            case ACCOUNT_LOCKED, ACCOUNT_DISABLED, REFRESH_REPLAY, ACCESS_DENIED
                    -> HttpStatus.FORBIDDEN;
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case CONFLICT -> HttpStatus.CONFLICT;
            case VALIDATION_ERROR -> HttpStatus.BAD_REQUEST;
            case INTERNAL_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }
}
