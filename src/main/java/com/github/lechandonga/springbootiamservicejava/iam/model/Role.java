package com.github.lechandonga.springbootiamservicejava.iam.model;

import java.util.HashSet;
import java.util.Set;

/** 角色，仅为角色名的集合载体，便于管理端展示与审计。 */
public class Role {

    private final String name;
    private final Set<String> members = new HashSet<>();

    public Role(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public Set<String> getMembers() {
        return members;
    }
}
