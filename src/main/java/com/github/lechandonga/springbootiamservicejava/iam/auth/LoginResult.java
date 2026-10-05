package com.github.lechandonga.springbootiamservicejava.iam.auth;

public record LoginResult(String accessToken, String refreshToken, String tokenType,
                          long expiresInSeconds, String sessionId) {
}
