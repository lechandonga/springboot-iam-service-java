package com.github.lechandonga.springbootiamservicejava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.springbootiamservicejava.config.IamProperties;
import com.github.lechandonga.springbootiamservicejava.domain.AuditRecord;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Append-only audit log. Sequence allocation and persistence happen in one
 * serialized critical section, guaranteeing a gapless, duplicate-free order
 * even under heavy concurrent authorization traffic. Records are kept in
 * memory (for verification/query) and appended as JSON lines to disk;
 * no update or delete API exists.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final IamProperties properties;
    private final ObjectMapper objectMapper;
    private final AtomicLong sequence = new AtomicLong(0);
    private final CopyOnWriteArrayList<AuditRecord> records = new CopyOnWriteArrayList<>();
    private Path logFile;

    public AuditService(IamProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    void init() throws IOException {
        logFile = Path.of(properties.getAuditLogFile());
        if (logFile.getParent() != null) {
            Files.createDirectories(logFile.getParent());
        }
    }

    public AuditRecord record(String eventType, String subject, String chainId,
                              String resource, String action, String result, String detail) {
        synchronized (this) {
            AuditRecord entry = new AuditRecord(
                    sequence.incrementAndGet(),
                    Instant.now(),
                    eventType,
                    subject,
                    chainId,
                    resource,
                    action,
                    result,
                    detail);
            records.add(entry);
            appendToFile(entry);
            return entry;
        }
    }

    private void appendToFile(AuditRecord entry) {
        try {
            String line = objectMapper.writeValueAsString(entry) + System.lineSeparator();
            Files.writeString(logFile, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            // Auditing must fail loudly rather than silently dropping entries.
            throw new IllegalStateException("failed to persist audit record", e);
        }
    }

    /** Immutable snapshot; callers can never modify the underlying log. */
    public List<AuditRecord> allRecords() {
        return List.copyOf(records);
    }

    public List<AuditRecord> bySubject(String subject) {
        return records.stream().filter(r -> subject.equals(r.subject())).toList();
    }

    public long count() {
        return records.size();
    }
}
