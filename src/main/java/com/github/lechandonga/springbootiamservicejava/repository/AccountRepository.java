package com.github.lechandonga.springbootiamservicejava.repository;

import com.github.lechandonga.springbootiamservicejava.domain.Account;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class AccountRepository {

    private final ConcurrentHashMap<String, Account> accounts = new ConcurrentHashMap<>();

    public Optional<Account> find(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    public Account save(Account account) {
        accounts.put(account.getUsername(), account);
        return account;
    }

    public boolean exists(String username) {
        return accounts.containsKey(username);
    }

    public List<Account> findAll() {
        return List.copyOf(accounts.values());
    }
}
