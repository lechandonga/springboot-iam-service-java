package com.github.lechandonga.springbootiamservicejava.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Emits human-readable, business-oriented test coverage logs:
 * {@code [IAM-场景] ...} headings and one line per case with its result,
 * so a test run shows which business scenarios and cases were exercised.
 */
public final class Scenario {

    private static final Logger log = LoggerFactory.getLogger("IAM-TEST-SCENARIOS");

    private Scenario() {
    }

    public static void begin(String scenario, String description) {
        log.info("[IAM-场景] ========== {} ==========", scenario);
        log.info("[IAM-场景] 覆盖业务: {}", description);
    }

    public static void caseStart(String name) {
        log.info("[IAM-用例] >> {}", name);
    }

    public static void pass(String name, String detail) {
        log.info("[IAM-用例]    {} => PASS | {}", name, detail);
    }

    public static void fail(String name, String detail) {
        log.error("[IAM-用例]    {} => FAIL | {}", name, detail);
    }

    public static void runCase(String name, ThrowingRunnable body) {
        caseStart(name);
        try {
            String detail = body.run();
            pass(name, detail == null ? "" : detail);
        } catch (AssertionError | RuntimeException e) {
            fail(name, e.getClass().getSimpleName() + ": " + e.getMessage());
            throw e;
        }
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        String run();
    }
}
