package com.github.lechandonga.springbootiamservicejava.iam.repo;

import com.github.lechandonga.springbootiamservicejava.iam.model.Account;
import com.github.lechandonga.springbootiamservicejava.iam.model.Role;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class AccountRepository {

    private final ConcurrentHashMap<String, Account> accounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Role> roles = new ConcurrentHashMap<>();

    public Optional<Account> find(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    public Account getRequired(String username) {
        return find(username).orElseThrow(() ->
                new com.github.lechandonga.springbootiamservicejava.iam.error.IamException(
                        com.github.lechandonga.springbootiamservicejava.iam.error.ErrorCode.ACCOUNT_NOT_FOUND));
    }

    public void save(Account account) {
        accounts.put(account.getUsername(), account);
    }

    public boolean create(Account account) {
        return accounts.putIfAbsent(account.getUsername(), account) == null;
    }

    public Role getOrCreateRole(String name) {
        return roles.computeIfAbsent(name, Role::new);
    }

    public List<String> listRoles() {
        return roles.keySet().stream().sorted().toList();
    }
}
