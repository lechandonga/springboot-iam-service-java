package com.github.lechandonga.springbootiamservicejava.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.springbootiamservicejava.domain.Account;
import com.github.lechandonga.springbootiamservicejava.domain.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.domain.IamException;
import com.github.lechandonga.springbootiamservicejava.domain.SessionChain;
import com.github.lechandonga.springbootiamservicejava.repository.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.repository.SessionRepository;
import com.github.lechandonga.springbootiamservicejava.service.TokenService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Authenticates Bearer access tokens and enforces live session/account state.
 * Revoked chains and disabled accounts are rejected on every request, so
 * permission or status changes take effect on already-issued tokens at once.
 */
@Component
public class AuthenticationFilter extends OncePerRequestFilter {

    public static final String ATTR_USERNAME = "iam.username";
    public static final String ATTR_CHAIN_ID = "iam.chainId";

    private static final String[] PUBLIC_PATHS = {
            "/api/auth/login", "/api/auth/refresh"
    };

    private final TokenService tokenService;
    private final SessionRepository sessionRepository;
    private final AccountRepository accountRepository;
    private final ObjectMapper objectMapper;

    public AuthenticationFilter(TokenService tokenService, SessionRepository sessionRepository,
                                AccountRepository accountRepository, ObjectMapper objectMapper) {
        this.tokenService = tokenService;
        this.sessionRepository = sessionRepository;
        this.accountRepository = accountRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        if (!path.startsWith("/api/")) {
            return true;
        }
        for (String publicPath : PUBLIC_PATHS) {
            if (publicPath.equals(path)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            writeError(response, ErrorCode.MISSING_TOKEN);
            return;
        }
        String rawToken = header.substring("Bearer ".length()).trim();
        try {
            JsonNode claims = tokenService.verify(rawToken, TokenService.TYPE_ACCESS);
            String username = claims.get("sub").asText();
            String chainId = claims.get("cid").asText();

            Account account = accountRepository.find(username)
                    .orElseThrow(() -> new IamException(ErrorCode.ACCESS_DENIED));
            if (!account.isEnabled()) {
                // Immediate enforcement: disabling an account invalidates all live sessions.
                throw new IamException(ErrorCode.ACCOUNT_DISABLED);
            }
            SessionChain sessionChain = sessionRepository.findChain(chainId)
                    .orElseThrow(() -> new IamException(ErrorCode.TOKEN_REVOKED));
            if (sessionChain.isRevoked()) {
                throw new IamException(ErrorCode.TOKEN_REVOKED);
            }

            request.setAttribute(ATTR_USERNAME, username);
            request.setAttribute(ATTR_CHAIN_ID, chainId);
            chain.doFilter(request, response);
        } catch (IamException e) {
            writeError(response, e.getErrorCode());
        }
    }

    private void writeError(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        HttpStatus status = errorCode == ErrorCode.ACCOUNT_DISABLED
                ? HttpStatus.FORBIDDEN
                : HttpStatus.UNAUTHORIZED;
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(),
                Map.of("code", errorCode.name(), "message", errorCode.safeMessage()));
    }
}
