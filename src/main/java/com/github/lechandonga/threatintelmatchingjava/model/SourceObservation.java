package com.github.lechandonga.threatintelmatchingjava.model;

import java.time.Instant;

/**
 * 单个来源对某个指标的一条情报观测。
 *
 * @param source        来源标识
 * @param disposition   来源结论
 * @param rawConfidence 来源给出的原始置信度（0-100）
 * @param observedAt    来源声称的观测时间
 * @param firstSeen     本服务首次收到该来源该指标的时间
 * @param lastSeen      本服务最近一次收到该来源该指标的时间
 * @param revision      该来源观测被实质性更新的次数
 */
public record SourceObservation(
        String source,
        Disposition disposition,
        int rawConfidence,
        Instant observedAt,
        Instant firstSeen,
        Instant lastSeen,
        int revision
) {
    public SourceObservation withRevision(Disposition disposition, int rawConfidence, Instant observedAt,
                                          Instant lastSeen, int revision) {
        return new SourceObservation(source, disposition, rawConfidence, observedAt, firstSeen, lastSeen, revision);
    }
}
