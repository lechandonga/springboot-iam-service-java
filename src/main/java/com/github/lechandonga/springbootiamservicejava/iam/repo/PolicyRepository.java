package com.github.lechandonga.springbootiamservicejava.iam.repo;

import com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode;
import com.github.lechandonga.springbootiamservicejava.iam.error.IamException;
import com.github.lechandonga.springbootiamservicejava.iam.model.Policy;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Repository
public class PolicyRepository {

    private final ConcurrentHashMap<String, Policy> byId = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Policy> ordered = new CopyOnWriteArrayList<>();

    public void save(Policy policy) {
        if (byId.putIfAbsent(policy.getId(), policy) == null) {
            ordered.add(policy);
        }
    }

    public Policy getRequired(String id) {
        Policy policy = byId.get(id);
        if (policy == null) {
            throw new IamException(ErrorCode.POLICY_NOT_FOUND);
        }
        return policy;
    }

    public Optional<Policy> find(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    /** 按策略登记顺序返回，保证 DENY/ALLOW 判定顺序稳定。 */
    public List<Policy> all() {
        return List.copyOf(ordered);
    }
}
