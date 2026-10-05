package com.github.lechandonga.springbootiamservicejava.iam.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.springbootiamservicejava.iam.auth.AuthService;
import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import com.github.lechandonga.springbootiamservicejava.iam.model.Account;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

/** 对 /api/protected/** 与 /api/admin/** 强制 Bearer 认证，并回源实时账号状态。 */
@Component
public class BearerTokenFilter extends OncePerRequestFilter {

    private final AuthService authService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public BearerTokenFilter(AuthService authService) {
        this.authService = authService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/protected/")
                && !path.startsWith("/api/admin/")
                && !path.equals("/api/auth/logout");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            String header = request.getHeader("Authorization");
            if (header == null || !header.startsWith("Bearer ")) {
                writeError(response, ErrorCode.TOKEN_MISSING);
                return;
            }
            String token = header.substring("Bearer ".length()).trim();
            AuthService.AuthenticatedAccess access = authService.validateAccessToken(token);
            SecurityContext.set(new CurrentPrincipal(access.account(), access.sessionId(), token));
            chain.doFilter(request, response);
        } catch (IamException ex) {
            writeError(response, ex.errorCode());
        } catch (Exception ex) {
            // 过滤器层也不透出底层异常
            logger.error("Authentication filter failure", ex);
            writeError(response, ErrorCode.INTERNAL_ERROR);
        } finally {
            SecurityContext.clear();
        }
    }

    private void writeError(HttpServletResponse response, ErrorCode code) throws IOException {
        response.setStatus(code == ErrorCode.ACCOUNT_DISABLED
                ? HttpStatus.FORBIDDEN.value() : code.httpStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), Map.of(
                "code", code.name(),
                "message", code.message(),
                "timestamp", Instant.now().toString()));
    }
}
