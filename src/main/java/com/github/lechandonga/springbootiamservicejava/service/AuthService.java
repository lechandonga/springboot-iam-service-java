package com.github.lechandonga.springbootiamservicejava.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.springbootiamservicejava.config.IamProperties;
import com.github.lechandonga.springbootiamservicejava.domain.Account;
import com.github.lechandonga.springbootiamservicejava.domain.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.domain.IamException;
import com.github.lechandonga.springbootiamservicejava.domain.SessionChain;
import com.github.lechandonga.springbootiamservicejava.repository.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.repository.SessionRepository;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {

    public record TokenPair(String accessToken, String refreshToken, String chainId,
                            Instant accessExpiresAt, Instant refreshExpiresAt) {}

    private final AccountRepository accountRepository;
    private final SessionRepository sessionRepository;
    private final PasswordService passwordService;
    private final TokenService tokenService;
    private final AuditService auditService;
    private final IamProperties properties;
    private final Map<String, Object> accountLocks = new ConcurrentHashMap<>();
    private Clock clock = Clock.systemUTC();

    public AuthService(AccountRepository accountRepository, SessionRepository sessionRepository,
                       PasswordService passwordService, TokenService tokenService,
                       AuditService auditService, IamProperties properties) {
        this.accountRepository = accountRepository;
        this.sessionRepository = sessionRepository;
        this.passwordService = passwordService;
        this.tokenService = tokenService;
        this.auditService = auditService;
        this.properties = properties;
    }

    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * Authenticates a username/password pair. Failure counting is serialized
     * per account so concurrent attempts cannot bypass the lock threshold.
     */
    public TokenPair login(String username, String rawPassword) {
        Account account = accountRepository.find(username).orElse(null);
        if (account == null) {
            auditService.record("LOGIN", username, null, null, null, "FAILURE",
                    "reason=unknown_username");
            throw new IamException(ErrorCode.BAD_CREDENTIALS);
        }

        Object lock = accountLocks.computeIfAbsent(username, k -> new Object());
        synchronized (lock) {
            Instant now = Instant.now(clock);
            if (!account.isEnabled()) {
                auditService.record("LOGIN", username, null, null, null, "FAILURE",
                        "reason=account_disabled");
                throw new IamException(ErrorCode.ACCOUNT_DISABLED);
            }
            if (account.getLockedUntil() != null) {
                if (account.getLockedUntil().isAfter(now)) {
                    auditService.record("LOGIN", username, null, null, null, "FAILURE",
                            "reason=account_locked;lockedUntil=" + account.getLockedUntil());
                    throw new IamException(ErrorCode.ACCOUNT_LOCKED);
                }
                // Lock window elapsed: give the account a fresh attempt budget.
                account.setLockedUntil(null);
                account.setFailedLoginCount(0);
            }

            if (!passwordService.matches(rawPassword, account.getPasswordHash())) {
                int failures = account.getFailedLoginCount() + 1;
                account.setFailedLoginCount(failures);
                if (failures >= properties.getMaxLoginFailures()) {
                    Instant lockedUntil = now.plus(properties.getLockDuration());
                    account.setLockedUntil(lockedUntil);
                    auditService.record("ACCOUNT_LOCKED", username, null, null, null, "DENY",
                            "policy=max-failed-logins:" + properties.getMaxLoginFailures()
                                    + ";lockedUntil=" + lockedUntil);
                }
                auditService.record("LOGIN", username, null, null, null, "FAILURE",
                        "reason=bad_credentials;failedCount=" + failures);
                throw new IamException(ErrorCode.BAD_CREDENTIALS);
            }

            account.setFailedLoginCount(0);
            account.setLockedUntil(null);
            return openSession(account);
        }
    }

    public TokenPair refresh(String rawRefreshToken) {
        JsonNode claims = tokenService.verify(rawRefreshToken, TokenService.TYPE_REFRESH);
        String username = claims.get("sub").asText();
        String chainId = claims.get("cid").asText();
        SessionChain chain = sessionRepository.findChain(chainId)
                .orElseThrow(() -> new IamException(ErrorCode.TOKEN_REVOKED));

        synchronized (chain) {
            String presentedHash = tokenService.sha256(rawRefreshToken);
            if (chain.isRevoked()) {
                // Presentation of a (now stale) token against an already revoked chain is
                // itself an abuse signal; keep the chain revoked and reject distinctly.
                if (chain.wasConsumed(presentedHash)) {
                    auditService.record("REFRESH_REPLAY", username, chainId, null, null, "DENY",
                            "policy=refresh-rotation;action=chain_already_revoked");
                    throw new IamException(ErrorCode.REFRESH_REPLAY);
                }
                auditService.record("REFRESH", username, chainId, null, null, "FAILURE",
                        "reason=chain_revoked;revokeReason=" + chain.getRevokeReason());
                throw new IamException(ErrorCode.TOKEN_REVOKED);
            }
            Account account = accountRepository.find(username)
                    .orElseThrow(() -> new IamException(ErrorCode.ACCOUNT_DISABLED));
            if (!account.isEnabled()) {
                chain.revoke("account_disabled");
                auditService.record("REFRESH", username, chainId, null, null, "FAILURE",
                        "reason=account_disabled");
                throw new IamException(ErrorCode.ACCOUNT_DISABLED);
            }

            String expectedHash = chain.getCurrentRefreshTokenHash();
            if (!constantTimeEquals(expectedHash, presentedHash) || chain.wasConsumed(presentedHash)) {
                // The token was validly signed but is no longer the current one:
                // it was already consumed. Treat as theft, revoke the whole chain.
                chain.revoke("refresh_token_replay");
                chain.markConsumed(presentedHash);
                auditService.record("REFRESH_REPLAY", username, chainId, null, null, "DENY",
                        "policy=refresh-rotation;action=revoke_chain");
                throw new IamException(ErrorCode.REFRESH_REPLAY);
            }

            TokenService.IssuedToken newAccess = tokenService.issueAccess(username, chainId);
            TokenService.IssuedToken newRefresh = tokenService.issueRefresh(username, chainId);
            chain.markConsumed(presentedHash);
            chain.setCurrentRefreshTokenHash(tokenService.sha256(newRefresh.raw()));
            auditService.record("REFRESH", username, chainId, null, null, "SUCCESS",
                    "policy=refresh-rotation;rotated=true");
            return new TokenPair(newAccess.raw(), newRefresh.raw(), chainId,
                    newAccess.expiresAt(), newRefresh.expiresAt());
        }
    }

    public void logout(String username, String chainId) {
        SessionChain chain = sessionRepository.findChain(chainId).orElse(null);
        if (chain != null) {
            synchronized (chain) {
                if (!chain.isRevoked()) {
                    chain.revoke("logout");
                }
            }
        }
        auditService.record("LOGOUT", username, chainId, null, null, "SUCCESS", "policy=session-owner");
    }

    private TokenPair openSession(Account account) {
        String chainId = UUID.randomUUID().toString();
        TokenService.IssuedToken access = tokenService.issueAccess(account.getUsername(), chainId);
        TokenService.IssuedToken refresh = tokenService.issueRefresh(account.getUsername(), chainId);
        SessionChain chain = new SessionChain(chainId, account.getUsername(),
                tokenService.sha256(refresh.raw()), Instant.now(clock));
        sessionRepository.save(chain);
        auditService.record("LOGIN", account.getUsername(), chainId, null, null, "SUCCESS",
                "policy=valid-credentials");
        return new TokenPair(access.raw(), refresh.raw(), chainId, access.expiresAt(), refresh.expiresAt());
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }
}
