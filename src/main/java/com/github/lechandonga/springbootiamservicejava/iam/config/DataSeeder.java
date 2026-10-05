package com.github.lechandonga.springbootiamservicejava.iam.config;

import com.github.lechandonga.springbootiamservicejava.iam.auth.AdminService;
import com.github.lechandonga.springbootiamservicejava.iam.model.Effect;
import com.github.lechandonga.springbootiamservicejava.iam.model.Policy;
import com.github.lechandonga.springbootiamservicejava.iam.repo.AccountRepository;
import com.github.lechandonga.springbootiamservicejava.iam.repo.PolicyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/** 本地演示/验证用种子数据。 */
@Configuration
public class DataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    @Bean
    CommandLineRunner seedIamData(AdminService adminService, AccountRepository accounts,
                                  PolicyRepository policyRepository) {
        return args -> {
            // 策略：默认拒绝，以下为最小权限放行与显式拒绝
            Policy adminAll = new Policy("p-admin-all", "iam.admin.*", Effect.ALLOW);
            adminAll.getRoles().add("admin");
            save(policyRepository, adminAll);

            Policy docRead = new Policy("p-doc-read", "document.read", Effect.ALLOW);
            docRead.getRoles().add("viewer");
            docRead.getRoles().add("editor");
            docRead.getRoles().add("admin");
            save(policyRepository, docRead);

            Policy docWrite = new Policy("p-doc-write-editor", "document.write", Effect.ALLOW);
            docWrite.getRoles().add("editor");
            save(policyRepository, docWrite);

            Policy docPublish = new Policy("p-doc-publish", "document.publish", Effect.ALLOW);
            docPublish.getRoles().add("editor");
            docPublish.getRequiredAttributes().add("department:content");
            save(policyRepository, docPublish);

            Policy probationDeny = new Policy("p-probation-deny-write", "document.write", Effect.DENY);
            probationDeny.getRequiredAttributes().add("probation");
            save(policyRepository, probationDeny);

            // 账号（口令均为加盐 PBKDF2 哈希）
            adminService.createAccount("admin", "admin-pass-123",
                    List.of("admin"), List.of("department:it"), true);
            adminService.createAccount("alice", "alice-pass-123",
                    List.of("editor"), List.of("department:content"), true);
            adminService.createAccount("bob", "bob-pass-123",
                    List.of("viewer"), List.of("department:sales"), true);
            adminService.createAccount("carol", "carol-pass-123",
                    List.of("editor"), List.of("department:content", "probation"), true);
            adminService.createAccount("dave", "dave-pass-123",
                    List.of("viewer"), List.of("department:sales"), false);

            log.info("IAM seed data loaded: admin/admin-pass-123, alice/alice-pass-123, "
                    + "bob/bob-pass-123, carol/carol-pass-123, dave(disabled)/dave-pass-123");
        };
    }

    private void save(PolicyRepository repository, Policy policy) {
        repository.find(policy.getId()).orElseGet(() -> {
            repository.save(policy);
            return policy;
        });
    }
}
