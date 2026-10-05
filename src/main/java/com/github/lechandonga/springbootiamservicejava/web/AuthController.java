package com.github.lechandonga.springbootiamservicejava.web;

import com.github.lechandonga.springbootiamservicejava.domain.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.domain.IamException;
import com.github.lechandonga.springbootiamservicejava.service.AuthService;
import com.github.lechandonga.springbootiamservicejava.web.dto.Requests;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Requests.LoginRequest request) {
        if (isBlank(request.username()) || isBlank(request.password())) {
            throw new IamException(ErrorCode.VALIDATION_ERROR, "username and password are required");
        }
        AuthService.TokenPair pair = authService.login(request.username(), request.password());
        return tokenBody(pair);
    }

    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody Requests.RefreshRequest request) {
        if (isBlank(request.refreshToken())) {
            throw new IamException(ErrorCode.VALIDATION_ERROR, "refreshToken is required");
        }
        AuthService.TokenPair pair = authService.refresh(request.refreshToken());
        return tokenBody(pair);
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest request) {
        String username = (String) request.getAttribute("iam.username");
        String chainId = (String) request.getAttribute("iam.chainId");
        authService.logout(username, chainId);
        return Map.of("result", "logged_out");
    }

    private Map<String, Object> tokenBody(AuthService.TokenPair pair) {
        return Map.of(
                "accessToken", pair.accessToken(),
                "refreshToken", pair.refreshToken(),
                "chainId", pair.chainId(),
                "accessExpiresAt", pair.accessExpiresAt(),
                "refreshExpiresAt", pair.refreshExpiresAt(),
                "issuedAt", Instant.now());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
