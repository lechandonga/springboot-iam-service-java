package com.github.lechandonga.springbootiamservicejava.iam.security;

import com.github.lechandonga.springbootiamservicejava.iam.model.Account;

public record CurrentPrincipal(Account account, String sessionId, String rawToken) {
}
