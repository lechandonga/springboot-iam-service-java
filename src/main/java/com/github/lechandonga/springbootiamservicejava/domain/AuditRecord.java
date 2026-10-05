package com.github.lechandonga.springbootiamservicejava.domain;

import java.time.Instant;

/**
 * Append-only audit entry. {@code sequence} is a gapless, process-wide
 * monotonic number so concurrent writers can neither lose nor duplicate
 * records. Records may be added but never modified or deleted.
 */
public record AuditRecord(
        long sequence,
        Instant timestamp,
        String eventType,
        String subject,
        String sessionChainId,
        String resource,
        String action,
        String result,
        String decisionDetail
) {
}
