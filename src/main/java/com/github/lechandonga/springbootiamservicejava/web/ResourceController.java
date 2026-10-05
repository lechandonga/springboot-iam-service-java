package com.github.lechandonga.springbootiamservicejava.web;

import com.github.lechandonga.springbootiamservicejava.domain.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.domain.IamException;
import com.github.lechandonga.springbootiamservicejava.service.AuthorizationService;
import com.github.lechandonga.springbootiamservicejava.web.dto.Requests;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/resource")
public class ResourceController {

    private final AuthorizationService authorizationService;

    public ResourceController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    /**
     * Explicit authorization decision endpoint: the caller asks whether
     * (resource, action) is permitted for the current live session.
     */
    @PostMapping("/access")
    public ResponseEntity<Map<String, Object>> checkAccess(@RequestBody Requests.AccessRequest body,
                                                           HttpServletRequest request) {
        if (body == null || isBlank(body.resource()) || isBlank(body.action())) {
            throw new IamException(ErrorCode.VALIDATION_ERROR, "resource and action are required");
        }
        String username = (String) request.getAttribute("iam.username");
        String chainId = (String) request.getAttribute("iam.chainId");
        AuthorizationService.Decision decision =
                authorizationService.authorize(username, chainId, body.resource(), body.action());
        Map<String, Object> payload = Map.of(
                "allowed", decision.allowed(),
                "resource", body.resource(),
                "action", body.action(),
                "detail", decision.detail());
        return decision.allowed()
                ? ResponseEntity.ok(payload)
                : ResponseEntity.status(HttpStatus.FORBIDDEN).body(payload);
    }

    /** Example of a protected operation; the same engine gates concrete actions. */
    @PostMapping("/documents/read")
    public ResponseEntity<Map<String, Object>> readDocument(HttpServletRequest request) {
        return gated(request, "document", "read");
    }

    @PostMapping("/documents/write")
    public ResponseEntity<Map<String, Object>> writeDocument(HttpServletRequest request) {
        return gated(request, "document", "write");
    }

    private ResponseEntity<Map<String, Object>> gated(HttpServletRequest request,
                                                      String resource, String action) {
        String username = (String) request.getAttribute("iam.username");
        String chainId = (String) request.getAttribute("iam.chainId");
        AuthorizationService.Decision decision =
                authorizationService.authorize(username, chainId, resource, action);
        if (!decision.allowed()) {
            throw new IamException(ErrorCode.ACCESS_DENIED, decision.detail());
        }
        return ResponseEntity.ok(Map.of(
                "resource", resource, "action", action, "result", "executed", "detail", decision.detail()));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
