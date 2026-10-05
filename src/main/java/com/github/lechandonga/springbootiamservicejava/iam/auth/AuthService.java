package com.github.lechandonga.springbootiamservicejava.iam.auth;

import com.github.lechandonga.springbootiamservicejava.iam.audit.AuditLog;
import com.github.lechandonga.springbootiamservicejava.iam.config.IamProperties;
import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import com.github.lechandonga.springbootiamservicejava.iam.model.Account;
import com.github.lechandonga.springbootiamservicejava.iam.model.RefreshTokenRecord;
import com.github.lechandonga.springbootiamservicejava.iam.model.Session;
import com.github.lechandonga.springbootiamservicejava.iam.repo.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.iam.repo.RefreshTokenRepository;
import com.github.lechandonga.springbootiamservicejava.iam.repo.SessionRepository;
import com.github.lechandonga.springbootiamservicejava.iam.security.PasswordEncoder;
import com.github.lechandonga.springbootiamservicejava.iam.token.AccessToken;
import com.github.lechandonga.springbootiamservicejava.iam.token.TokenException;
import com.github.lechandonga.springbootiamservicejava.iam.token.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public record AuthenticatedAccess(Account account, String sessionId) {
    }

    /** 账号不存在时也执行一次哈希比较，降低用户名枚举的时间侧信道。 */
    private static final String DUMMY_STORED =
            "pbkdf2$120000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private final AccountRepository accounts;
    private final SessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuditLog auditLog;
    private final IamProperties properties;

    public AuthService(AccountRepository accounts, SessionRepository sessions,
                       RefreshTokenRepository refreshTokens, PasswordEncoder passwordEncoder,
                       TokenService tokenService, AuditLog auditLog, IamProperties properties) {
        this.accounts = accounts;
        this.sessions = sessions;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.auditLog = auditLog;
        this.properties = properties;
    }

    public LoginResult login(String username, String rawPassword) {
        if (username == null || username.isBlank() || rawPassword == null) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        Account account = accounts.find(username).orElse(null);
        if (account == null) {
            passwordEncoder.matches(rawPassword == null ? "" : rawPassword, DUMMY_STORED);
            audit(username, null, "auth.login", "FAILURE", null, "no_such_account");
            throw new IamException(ErrorCode.INVALID_CREDENTIALS);
        }

        // 对同一账号对象加锁：并发失败登录串行计数，无法靠并发把阈值“摊薄”。
        synchronized (account) {
            Instant now = tokenService.now();
            if (account.getLockedUntil() != null) {
                if (now.isBefore(account.getLockedUntil())) {
                    audit(username, null, "auth.login", "FAILURE", null, "account_locked");
                    throw new IamException(ErrorCode.ACCOUNT_LOCKED);
                }
                account.setLockedUntil(null);
                account.setFailedAttempts(0);
            }
            if (!account.isEnabled()) {
                audit(username, null, "auth.login", "FAILURE", null, "account_disabled");
                throw new IamException(ErrorCode.ACCOUNT_DISABLED);
            }
            if (!passwordEncoder.matches(rawPassword, account.getPasswordHash())) {
                int failures = account.getFailedAttempts() + 1;
                account.setFailedAttempts(failures);
                String reason = "bad_credentials";
                if (failures >= properties.getMaxFailedAttempts()) {
                    account.setLockedUntil(now.plus(properties.getLockDuration()));
                    reason = "bad_credentials_threshold_reached_account_locked";
                    log.warn("Account {} locked until {} after {} failed attempts",
                            username, account.getLockedUntil(), failures);
                }
                audit(username, null, "auth.login", "FAILURE", null, reason);
                throw new IamException(ErrorCode.INVALID_CREDENTIALS);
            }

            account.setFailedAttempts(0);
            account.setLockedUntil(null);
            return openSession(account, "login");
        }
    }

    /** 校验访问令牌并回源账号/会话的实时状态。任何一项不满足都给出可区分的拒绝原因。 */
    public AuthenticatedAccess validateAccessToken(String token) {
        TokenService.Payload payload = tokenService.verify(token);
        Session session = sessions.find(payload.sid())
                .orElseThrow(() -> new TokenException(ErrorCode.TOKEN_REVOKED));
        if (session.isRevoked()) {
            throw new TokenException(ErrorCode.TOKEN_REVOKED);
        }
        Account account = accounts.find(payload.sub())
                .orElseThrow(() -> new TokenException(ErrorCode.TOKEN_REVOKED));
        if (!account.isEnabled()) {
            throw new IamException(ErrorCode.ACCOUNT_DISABLED);
        }
        if (payload.ver() != account.getSecurityVersion()) {
            // 禁用/权限/口令调整后旧令牌立即失效
            throw new TokenException(ErrorCode.TOKEN_REVOKED);
        }
        return new AuthenticatedAccess(account, session.getId());
    }

    /**
     * 刷新令牌轮换：旧令牌一次性作废，签发新访问令牌 + 新刷新令牌（同一会话链）。
     * 旧刷新令牌若被再次使用，判定为盗用，立即吊销整条会话链。
     */
    public LoginResult refresh(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        String tokenHash = passwordEncoder.sha256(rawRefreshToken);
        RefreshTokenRecord record = refreshTokens.find(tokenHash)
                .orElseThrow(() -> {
                    audit(null, null, "auth.refresh", "FAILURE", null, "unknown_refresh_token");
                    return new TokenException(ErrorCode.TOKEN_REVOKED);
                });

        synchronized (record) {
            if (record.isUsed()) {
                Session stolen = sessions.find(record.getSessionId()).orElse(null);
                if (stolen != null && !stolen.isRevoked()) {
                    stolen.revoke("refresh_token_reuse_detected");
                }
                audit(record.getUsername(), record.getSessionId(), "auth.refresh", "FAILURE",
                        null, "refresh_token_reuse_chain_revoked");
                log.warn("Refresh token reuse detected for {}; session chain {} revoked",
                        record.getUsername(), record.getSessionId());
                throw new TokenException(ErrorCode.TOKEN_REVOKED);
            }
            if (tokenService.now().isAfter(record.getExpiresAt())) {
                record.markUsed();
                audit(record.getUsername(), record.getSessionId(), "auth.refresh", "FAILURE",
                        null, "refresh_token_expired");
                throw new TokenException(ErrorCode.TOKEN_EXPIRED);
            }
            Session session = sessions.find(record.getSessionId())
                    .orElseThrow(() -> new TokenException(ErrorCode.TOKEN_REVOKED));
            if (session.isRevoked()) {
                record.markUsed();
                audit(record.getUsername(), session.getId(), "auth.refresh", "FAILURE",
                        null, "session_revoked");
                throw new TokenException(ErrorCode.TOKEN_REVOKED);
            }
            Account account = accounts.find(record.getUsername())
                    .orElseThrow(() -> new TokenException(ErrorCode.TOKEN_REVOKED));
            if (!account.isEnabled()) {
                record.markUsed();
                session.revoke("account_disabled");
                audit(account.getUsername(), session.getId(), "auth.refresh", "FAILURE",
                        null, "account_disabled");
                throw new IamException(ErrorCode.ACCOUNT_DISABLED);
            }

            record.markUsed();
            return issueTokens(account, session, "auth.refresh", "refresh_rotated");
        }
    }

    public void logout(String sessionId, String username) {
        Session session = sessions.find(sessionId).orElse(null);
        if (session != null) {
            synchronized (session) {
                if (!session.isRevoked()) {
                    session.revoke("user_logout");
                }
            }
        }
        audit(username, sessionId, "auth.logout", "SUCCESS", null, "user_logout");
    }

    private LoginResult openSession(Account account, String trigger) {
        Session session = new Session(UUID.randomUUID().toString(), account.getUsername(),
                account.getSecurityVersion());
        sessions.save(session);
        return issueTokens(account, session, trigger, "session_created");
    }

    private LoginResult issueTokens(Account account, Session session, String action, String reason) {
        AccessToken accessToken = tokenService.issueAccessToken(
                account.getUsername(), session.getId(), account.getSecurityVersion());
        String rawRefresh = tokenService.generateRefreshTokenRaw();
        refreshTokens.save(new RefreshTokenRecord(
                passwordEncoder.sha256(rawRefresh), session.getId(), account.getUsername(),
                tokenService.refreshTokenExpiry()));
        audit(account.getUsername(), session.getId(), action, "SUCCESS", null, reason);
        return new LoginResult(accessToken.token(), rawRefresh, "Bearer",
                properties.getAccessTokenTtl().toSeconds(), session.getId());
    }

    private void audit(String principal, String sessionId, String action, String result,
                       String policyId, String reason) {
        auditLog.append(principal, sessionId, action, result, policyId, reason, Map.of());
    }
}
