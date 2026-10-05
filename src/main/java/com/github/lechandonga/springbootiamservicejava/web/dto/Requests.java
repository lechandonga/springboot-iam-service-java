package com.github.lechandonga.springbootiamservicejava.web.dto;

import java.util.Map;
import java.util.Set;

public class Requests {

    public record LoginRequest(String username, String password) {}

    public record RefreshRequest(String refreshToken) {}

    public record CreateAccountRequest(String username, String password,
                                      Set<String> roles, Map<String, String> attributes) {}

    public record PasswordChangeRequest(String newPassword) {}

    public record StatusRequest(boolean enabled) {}

    public record RolesRequest(Set<String> roles) {}

    public record AttributesRequest(Map<String, String> attributes) {}

    public record AccessRequest(String resource, String action) {}

    public record PolicyRequest(String id, String subject, String resource,
                                String action, String effect, int priority) {}
}
