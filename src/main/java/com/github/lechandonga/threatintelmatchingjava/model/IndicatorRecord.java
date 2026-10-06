package com.github.lechandonga.threatintelmatchingjava.model;

import java.time.Instant;
import java.util.Map;

/**
 * 合并后的指标记录，按来源保留各自的观测。
 * 本对象不可变；更新时由存储层整体替换，保证查询不会读到中间状态。
 */
public record IndicatorRecord(
        IndicatorKey key,
        Map<String, SourceObservation> observations,
        Instant createdAt,
        int revision
) {
}
