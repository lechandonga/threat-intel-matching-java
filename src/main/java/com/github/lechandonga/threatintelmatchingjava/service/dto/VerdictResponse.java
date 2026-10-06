package com.github.lechandonga.threatintelmatchingjava.service.dto;

import java.time.Instant;
import java.util.List;

/**
 * 判定查询响应：最终结论 + 完整可追溯依据。
 */
public record VerdictResponse(
        String type,
        String value,
        String verdict,
        boolean whitelisted,
        boolean found,
        String decidingRule,
        String decidingSource,
        double halfLifeDays,
        Instant evaluatedAt,
        List<SourceView> sources
) {
}
