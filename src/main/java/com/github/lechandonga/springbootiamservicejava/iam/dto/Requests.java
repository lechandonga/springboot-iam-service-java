package com.github.lechandonga.springbootiamservicejava.iam.dto;

import java.util.List;

public final class Requests {

    private Requests() {
    }

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    public record CheckRequest(String action) {
    }

    public record CreateAccountRequest(String username, String password, List<String> roles,
                                       List<String> attributes, Boolean enabled) {
    }

    public record UpdateAccountRequest(Boolean enabled, List<String> roles, List<String> attributes,
                                       String password) {
    }

    public record PolicyRequest(String id, String action, String effect, List<String> roles,
                                List<String> requiredAttributes) {
    }
}
