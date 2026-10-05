package com.github.lechandonga.springbootiamservicejava.iam.token;

import java.time.Instant;

public record AccessToken(String token, String username, String sessionId, long securityVersion,
                          Instant issuedAt, Instant expiresAt) {
}
