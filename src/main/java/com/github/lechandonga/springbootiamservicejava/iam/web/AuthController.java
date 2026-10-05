package com.github.lechandonga.springbootiamservicejava.iam.web;

import com.github.lechandonga.springbootiamservicejava.iam.auth.AuthService;
import com.github.lechandonga.springbootiamservicejava.iam.auth.LoginResult;
import com.github.lechandonga.springbootiamservicejava.iam.dto.Requests;
import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import com.github.lechandonga.springbootiamservicejava.iam.security.SecurityContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
        if (request == null || request.username() == null || request.password() == null) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        return toBody(authService.login(request.username(), request.password()));
    }

    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody Requests.RefreshRequest request) {
        if (request == null || request.refreshToken() == null) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        return toBody(authService.refresh(request.refreshToken()));
    }

    @PostMapping("/logout")
    public Map<String, Object> logout() {
        var principal = SecurityContext.required();
        authService.logout(principal.sessionId(), principal.account().getUsername());
        return Map.of("status", "logged_out");
    }

    private Map<String, Object> toBody(LoginResult result) {
        return Map.of(
                "accessToken", result.accessToken(),
                "refreshToken", result.refreshToken(),
                "tokenType", result.tokenType(),
                "expiresIn", result.expiresInSeconds(),
                "sessionId", result.sessionId());
    }
}
