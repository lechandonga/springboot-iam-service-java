package com.github.lechandonga.springbootiamservicejava.iam.token;

import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;

public class TokenException extends IamException {
    public TokenException(ErrorCode errorCode) {
        super(errorCode);
    }
}
