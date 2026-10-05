package com.github.lechandonga.springbootiamservicejava.config;

import com.github.lechandonga.springbootiamservicejava.domain.Account;
import com.github.lechandonga.springbootiamservicejava.domain.Policy;
import com.github.lechandonga.springbootiamservicejava.repository.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.repository.PolicyRepository;
import com.github.lechandonga.springbootiamservicejava.service.PasswordService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;

import java.util.Map;

@Configuration
@EnableConfigurationProperties(IamProperties.class)
public class IamConfig {

    private final AccountRepository accountRepository;
    private final PolicyRepository policyRepository;
    private final PasswordService passwordService;

    public IamConfig(AccountRepository accountRepository, PolicyRepository policyRepository,
                     PasswordService passwordService) {
        this.accountRepository = accountRepository;
        this.policyRepository = policyRepository;
        this.passwordService = passwordService;
    }

    /**
     * Seeds a reproducible local dataset so the service is verifiable
     * out of the box. Only runs when the stores are empty.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void seed() {
        if (accountRepository.findAll().isEmpty()) {
            seedAccount("admin", "admin123", new String[]{"admin"}, Map.of());
            seedAccount("alice", "alice123", new String[]{"viewer"},
                    Map.of("department", "engineering"));
            seedAccount("bob", "bob123", new String[]{"editor"},
                    Map.of("department", "marketing"));
        }
        if (policyRepository.findAllOrderedByPriority().isEmpty()) {
            policyRepository.save(new Policy("p-admin", "role:admin", "admin:*", "*",
                    Policy.Effect.ALLOW, 10));
            policyRepository.save(new Policy("p-doc-admin", "role:admin", "document*", "*",
                    Policy.Effect.ALLOW, 20));
            policyRepository.save(new Policy("p-doc-read-eng", "attr:department=engineering",
                    "document", "read", Policy.Effect.ALLOW, 30));
            policyRepository.save(new Policy("p-doc-write-editor", "role:editor",
                    "document", "write", Policy.Effect.ALLOW, 40));
        }
    }

    private void seedAccount(String username, String password, String[] roles,
                             Map<String, String> attributes) {
        Account account = new Account(username, passwordService.hash(password));
        account.getRoles().addAll(java.util.List.of(roles));
        account.getAttributes().putAll(attributes);
        accountRepository.save(account);
    }
}
