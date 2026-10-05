package com.github.lechandonga.springbootiamservicejava.tests.iam;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 场景化日志：跑测试时从日志即可看出覆盖的业务场景、用例与结果。 */
public final class ScenarioLog {

    private static final Logger log = LoggerFactory.getLogger("IAM-SCENARIO");

    private ScenarioLog() {
    }

    public static void scenario(String name) {
        log.info("【业务场景】========== {} ==========", name);
    }

    public static void step(String caseName, String expectation) {
        log.info("【用例】{} | 预期: {}", caseName, expectation);
    }

    public static void pass(String detail) {
        log.info("【结果】PASS | {}", detail);
    }

    public static void info(String detail) {
        log.info("【说明】{}", detail);
    }
}
