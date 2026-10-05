package com.github.lechandonga.springbootiamservicejava.iam.repo;

import com.github.lechandonga.springbootiamservicejava.iam.model.RefreshTokenRecord;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class RefreshTokenRepository {

    private final ConcurrentHashMap<String, RefreshTokenRecord> tokens = new ConcurrentHashMap<>();

    public void save(RefreshTokenRecord record) {
        tokens.put(record.getTokenHash(), record);
    }

    public Optional<RefreshTokenRecord> find(String tokenHash) {
        return Optional.ofNullable(tokens.get(tokenHash));
    }
}
