package com.github.lechandonga.springbootiamservicejava.iam.authz;

import com.github.lechandonga.springbootiamservicejava.iam.model.Effect;

public record Decision(boolean allowed, Effect effect, String matchedPolicyId, String reason) {

    public static Decision allow(String policyId) {
        return new Decision(true, Effect.ALLOW, policyId, "matched_allow_policy");
    }

    public static Decision explicitDeny(String policyId) {
        return new Decision(false, Effect.DENY, policyId, "matched_deny_policy");
    }

    public static Decision defaultDeny(String reason) {
        return new Decision(false, Effect.DENY, null, reason);
    }
}
