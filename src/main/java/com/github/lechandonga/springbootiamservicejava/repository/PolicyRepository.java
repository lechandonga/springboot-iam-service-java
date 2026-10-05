package com.github.lechandonga.springbootiamservicejava.repository;

import com.github.lechandonga.springbootiamservicejava.domain.Policy;
import org.springframework.stereotype.Repository;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

@Repository
public class PolicyRepository {

    private final CopyOnWriteArrayList<Policy> policies = new CopyOnWriteArrayList<>();

    public Policy save(Policy policy) {
        delete(policy.getId());
        policies.add(policy);
        return policy;
    }

    public boolean delete(String id) {
        return policies.removeIf(p -> p.getId().equals(id));
    }

    public Optional<Policy> find(String id) {
        return policies.stream().filter(p -> p.getId().equals(id)).findFirst();
    }

    /** Snapshot ordered by priority (smaller first). */
    public List<Policy> findAllOrderedByPriority() {
        return policies.stream().sorted(Comparator.comparingInt(Policy::getPriority)).toList();
    }
}
