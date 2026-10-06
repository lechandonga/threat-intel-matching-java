package com.github.lechandonga.threatintelmatchingjava.service.dto;

import java.time.Instant;

/**
 * 查询结果中单个来源的依据视图。
 */
public record SourceView(
        String source,
        String disposition,
        int rawConfidence,
        double decayedConfidence,
        double score,
        Instant observedAt,
        Instant firstSeen,
        Instant lastSeen,
        int revision,
        boolean deciding
) {
}
