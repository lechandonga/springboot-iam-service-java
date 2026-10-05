package com.github.lechandonga.springbootiamservicejava.iam.web;

import com.github.lechandonga.springbootiamservicejava.iam.authz.AuthorizationService;
import com.github.lechandonga.springbootiamservicejava.iam.authz.Decision;
import com.github.lechandonga.springbootiamservicejava.iam.dto.Requests;
import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import com.github.lechandonga.springbootiamservicejava.iam.security.CurrentPrincipal;
import com.github.lechandonga.springbootiamservicejava.iam.security.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/protected")
public class ProtectedController {

    private final AuthorizationService authorizationService;

    public ProtectedController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    /** 示例受保护资源，仅要求通过认证。 */
    @GetMapping("/profile")
    public Map<String, Object> profile() {
        CurrentPrincipal principal = SecurityContext.required();
        return Map.of(
                "username", principal.account().getUsername(),
                "roles", principal.account().getRoles().stream().sorted().toList(),
                "attributes", principal.account().getAttributes().stream().sorted().toList(),
                "sessionId", principal.sessionId());
    }

    /** 显式授权判定入口：对 action 做最小权限判定，每次判定写一条审计。 */
    @PostMapping("/check")
    public Map<String, Object> check(@RequestBody Requests.CheckRequest request) {
        if (request == null || request.action() == null || request.action().isBlank()) {
            throw new IamException(ErrorCode.BAD_REQUEST);
        }
        CurrentPrincipal principal = SecurityContext.required();
        Decision decision = authorizationService.enforce(
                principal.account(), principal.sessionId(), request.action(),
                Map.of("via", "api/protected/check"));
        if (!decision.allowed()) {
            throw new IamException(ErrorCode.ACCESS_DENIED, decision.reason());
        }
        return Map.of(
                "action", request.action(),
                "allowed", true,
                "matchedPolicyId", decision.matchedPolicyId() == null ? "" : decision.matchedPolicyId());
    }
}
