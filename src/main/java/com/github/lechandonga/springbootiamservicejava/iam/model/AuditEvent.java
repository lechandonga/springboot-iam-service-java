package com.github.lechandonga.springbootiamservicejava.iam.model;

import java.time.Instant;
import java.util.Map;

/** 只增不改的审计记录，可还原“谁/何时/对什么操作/依据哪条策略/什么结果”。 */
public class AuditEvent {

    private final long sequence;
    private final Instant timestamp;
    private final String principal;
    private final String sessionId;
    private final String action;
    private final String result;
    private final String matchedPolicyId;
    private final String reason;
    private final Map<String, Object> detail;

    public AuditEvent(long sequence, Instant timestamp, String principal, String sessionId, String action,
                      String result, String matchedPolicyId, String reason, Map<String, Object> detail) {
        this.sequence = sequence;
        this.timestamp = timestamp;
        this.principal = principal;
        this.sessionId = sessionId;
        this.action = action;
        this.result = result;
        this.matchedPolicyId = matchedPolicyId;
        this.reason = reason;
        this.detail = detail;
    }

    public long getSequence() {
        return sequence;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getAction() {
        return action;
    }

    public String getResult() {
        return result;
    }

    public String getMatchedPolicyId() {
        return matchedPolicyId;
    }

    public String getReason() {
        return reason;
    }

    public Map<String, Object> getDetail() {
        return detail;
    }
}
