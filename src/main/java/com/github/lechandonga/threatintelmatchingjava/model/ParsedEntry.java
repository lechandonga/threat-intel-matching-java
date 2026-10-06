package com.github.lechandonga.threatintelmatchingjava.model;

import java.time.Instant;

/**
 * 归一化后、待写入存储的一条情报条目。
 */
public record ParsedEntry(
        String source,
        IndicatorType type,
        String value,
        Disposition disposition,
        int confidence,
        Instant observedAt,
        boolean revoked
) {
    public IndicatorKey key() {
        return new IndicatorKey(type, value);
    }
}
