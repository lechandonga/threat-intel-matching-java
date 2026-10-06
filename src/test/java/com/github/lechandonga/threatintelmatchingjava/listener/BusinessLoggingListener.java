package com.github.lechandonga.threatintelmatchingjava.listener;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 让测试日志能看出覆盖了哪些业务、各业务的用例与通过情况。
 */
public class BusinessLoggingListener implements TestExecutionListener {

    private static final Map<String, String> BUSINESS_GROUPS = new LinkedHashMap<>();

    static {
        BUSINESS_GROUPS.put("BadDataRejectionTest", "业务1: 坏数据逐条拒绝（字段缺失/格式非法/取值越界）");
        BUSINESS_GROUPS.put("MergeWithdrawIdempotencyTest", "业务2: 多来源合并 / 撤回 / 幂等导入");
        BUSINESS_GROUPS.put("VerdictAdjudicationTest", "业务3: 冲突裁决 / 置信度衰减 / 白名单优先 / 顺序无关");
        BUSINESS_GROUPS.put("ConcurrencyTest", "业务4: 并发导入与查询（无重复计数/更新丢失/中间态）");
        BUSINESS_GROUPS.put("IntelApiWebTest", "业务5: REST 接口端到端（导入/查询/白名单/拒绝原因）");
        BUSINESS_GROUPS.put("ApplicationTests", "业务6: Spring 上下文装配");
    }

    private String currentClass;
    private int passed;
    private int failed;
    private static final Pattern CLASS_SEGMENT = Pattern.compile("\\[class:([^\\]]+)]");

    @Override
    public void executionStarted(TestIdentifier id) {
        if (id.isTest()) {
            String className = simpleClass(id);
            if (!className.equals(currentClass)) {
                finishGroup();
                currentClass = className;
                System.out.println();
                System.out.println("========== " + BUSINESS_GROUPS.getOrDefault(className, "业务: " + className)
                        + " ==========");
            }
            System.out.println("[用例] " + id.getDisplayName());
        }
    }

    @Override
    public void executionFinished(TestIdentifier id, TestExecutionResult result) {
        if (id.isTest()) {
            if (result.getStatus() == TestExecutionResult.Status.SUCCESSFUL) {
                passed++;
                System.out.println("  -> 通过 PASS");
            } else {
                failed++;
                String cause = result.getThrowable().map(Throwable::getMessage).orElse("无异常信息");
                System.out.println("  -> 失败 FAIL: " + cause);
            }
        }
    }

    @Override
    public void testPlanExecutionFinished(org.junit.platform.launcher.TestPlan testPlan) {
        finishGroup();
        System.out.println();
        System.out.println("########## 全部用例执行结束 ##########");
    }

    private void finishGroup() {
        if (currentClass != null) {
            System.out.println("---- 小结 [" + BUSINESS_GROUPS.getOrDefault(currentClass, currentClass)
                    + "] 通过=" + passed + " 失败=" + failed + " ----");
            passed = 0;
            failed = 0;
        }
    }

    private String simpleClass(TestIdentifier id) {
        String uniqueId = id.getUniqueId();
        Matcher matcher = CLASS_SEGMENT.matcher(uniqueId);
        if (matcher.find()) {
            String fqcn = matcher.group(1);
            String simple = fqcn.substring(fqcn.lastIndexOf('.') + 1);
            if (BUSINESS_GROUPS.containsKey(simple)) {
                return simple;
            }
        }
        return uniqueId;
    }
}
