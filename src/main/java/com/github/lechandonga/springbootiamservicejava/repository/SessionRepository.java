package com.github.lechandonga.springbootiamservicejava.repository;

import com.github.lechandonga.springbootiamservicejava.domain.SessionChain;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class SessionRepository {

    private final ConcurrentHashMap<String, SessionChain> chains = new ConcurrentHashMap<>();

    public SessionChain save(SessionChain chain) {
        chains.put(chain.getChainId(), chain);
        return chain;
    }

    public Optional<SessionChain> findChain(String chainId) {
        return Optional.ofNullable(chains.get(chainId));
    }

    public List<SessionChain> findByUsername(String username) {
        return chains.values().stream().filter(c -> c.getUsername().equals(username)).toList();
    }

    public void revokeAllFor(String username, String reason) {
        chains.values().stream()
                .filter(c -> c.getUsername().equals(username) && !c.isRevoked())
                .forEach(c -> c.revoke(reason));
    }
}
