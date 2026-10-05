package com.github.lechandonga.springbootiamservicejava.iam.model;

import java.util.HashSet;
import java.util.Set;

/**
 * 授权策略。一条策略同时约束操作、角色与账号属性，三者全部命中才生效。
 * 判定顺序：命中的 DENY 优先；否则命中 ALLOW 放行；否则默认拒绝。
 */
public class Policy {

    private final String id;
    private final String action;
    private final Set<String> roles = new HashSet<>();
    private final Set<String> requiredAttributes = new HashSet<>();
    private final Effect effect;

    public Policy(String id, String action, Effect effect) {
        this.id = id;
        this.action = action;
        this.effect = effect;
    }

    public String getId() {
        return id;
    }

    public String getAction() {
        return action;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getRequiredAttributes() {
        return requiredAttributes;
    }

    public Effect getEffect() {
        return effect;
    }
}
