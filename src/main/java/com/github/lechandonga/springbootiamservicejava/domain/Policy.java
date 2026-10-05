package com.github.lechandonga.springbootiamservicejava.domain;

/**
 * An authorization policy. Every request is evaluated against every policy:
 * the first matching policy (in priority order) decides ALLOW or DENY.
 * If no policy matches, the result is DENY (default-deny / least privilege).
 *
 * Resource/action support trailing wildcard matching, e.g. "doc:*" or "doc:read".
 * subject may be a role name ("role:admin"), an account attribute
 * ("attr:department=engineering") or "*" for any authenticated subject.
 */
public class Policy {

    private final String id;
    private final String subject;
    private final String resource;
    private final String action;
    private final Effect effect;
    private int priority;

    public enum Effect { ALLOW, DENY }

    public Policy(String id, String subject, String resource, String action, Effect effect, int priority) {
        this.id = id;
        this.subject = subject;
        this.resource = resource;
        this.action = action;
        this.effect = effect;
        this.priority = priority;
    }

    public String getId() { return id; }
    public String getSubject() { return subject; }
    public String getResource() { return resource; }
    public String getAction() { return action; }
    public Effect getEffect() { return effect; }
    public int getPriority() { return priority; }
    public void setPriority(int priority) { this.priority = priority; }
}
