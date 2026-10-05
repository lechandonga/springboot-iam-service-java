package com.github.lechandonga.springbootiamservicejava.iam.audit;

import com.github.lechandonga.springbootiamservicejava.iam.model.AuditEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 只增不改的审计日志。
 * append 在单一锁内分配严格递增序列号并落盘内存列表：并发写入不会丢记录、不会出现重号；
 * 对外不提供任何更新/删除入口。
 */
@Component
public class AuditLog {

    private final Object appendLock = new Object();
    private final List<AuditEvent> events = new ArrayList<>();
    private long nextSequence = 1;

    public AuditEvent append(String principal, String sessionId, String action, String result,
                             String matchedPolicyId, String reason, Map<String, Object> detail) {
        synchronized (appendLock) {
            AuditEvent event = new AuditEvent(nextSequence, Instant.now(), principal, sessionId, action,
                    result, matchedPolicyId, reason,
                    detail == null ? Map.of() : new LinkedHashMap<>(detail));
            events.add(event);
            nextSequence++;
            return event;
        }
    }

    /** 返回快照，调用方无法修改底层记录。 */
    public List<AuditEvent> all() {
        synchronized (appendLock) {
            return List.copyOf(events);
        }
    }

    public int size() {
        synchronized (appendLock) {
            return events.size();
        }
    }

    public long maxSequence() {
        synchronized (appendLock) {
            return nextSequence - 1;
        }
    }
}
