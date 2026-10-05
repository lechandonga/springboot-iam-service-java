package com.github.lechandonga.springbootiamservicejava.iam.repo;

import com.github.lechandonga.springbootiamservicejava.iam.model.Session;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class SessionRepository {

    private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();

    public void save(Session session) {
        sessions.put(session.getId(), session);
    }

    public Optional<Session> find(String id) {
        return Optional.ofNullable(sessions.get(id));
    }
}
