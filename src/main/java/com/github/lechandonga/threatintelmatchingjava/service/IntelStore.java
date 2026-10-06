package com.github.lechandonga.threatintelmatchingjava.service;

import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorKey;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorRecord;
import com.github.lechandonga.threatintelmatchingjava.model.ParsedEntry;
import com.github.lechandonga.threatintelmatchingjava.model.RejectedRecord;
import com.github.lechandonga.threatintelmatchingjava.model.SourceObservation;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 情报指标的内存存储与合并/撤回逻辑。
 * <p>并发策略：所有读写都在同一把锁下原子完成，且对外返回的对象均为快照副本，
 * 因此导入与查询并发时不会出现重复计数、更新丢失或读到中间状态。
 */
public class IntelStore {

    private final Map<IndicatorKey, IndicatorRecord> records = new LinkedHashMap<>();
    private final Clock clock;

    public IntelStore(Clock clock) {
        this.clock = clock;
    }

    /**
     * 原子应用一整个解析后的批次（坏数据已在解析阶段剔除）。
     */
    public synchronized ImportResult apply(List<ParsedEntry> entries, List<RejectedRecord> rejected) {
        int accepted = 0;
        int unchanged = 0;
        int revoked = 0;
        int alreadyAbsent = 0;
        Instant now = clock.instant();

        for (ParsedEntry entry : entries) {
            IndicatorKey key = entry.key();
            IndicatorRecord existing = records.get(key);
            Map<String, SourceObservation> observations =
                    existing == null ? new LinkedHashMap<>() : new LinkedHashMap<>(existing.observations());

            if (entry.revoked()) {
                if (!observations.containsKey(entry.source())) {
                    alreadyAbsent++;
                    continue;
                }
                observations.remove(entry.source());
                revoked++;
                if (observations.isEmpty()) {
                    records.remove(key);
                } else {
                    putRecord(key, observations, existing, now);
                }
                continue;
            }

            SourceObservation prior = observations.get(entry.source());
            if (prior != null
                    && prior.disposition() == entry.disposition()
                    && prior.rawConfidence() == entry.confidence()
                    && prior.observedAt().equals(entry.observedAt())) {
                unchanged++;
                continue;
            }

            SourceObservation observation = new SourceObservation(
                    entry.source(),
                    entry.disposition(),
                    entry.confidence(),
                    entry.observedAt(),
                    prior == null ? now : prior.firstSeen(),
                    now,
                    prior == null ? 1 : prior.revision() + 1
            );
            observations.put(entry.source(), observation);
            putRecord(key, observations, existing, now);
            accepted++;
        }
        return new ImportResult(accepted, unchanged, revoked, alreadyAbsent, List.copyOf(rejected));
    }

    private void putRecord(IndicatorKey key, Map<String, SourceObservation> observations,
                           IndicatorRecord existing, Instant now) {
        records.put(key, new IndicatorRecord(
                key,
                Map.copyOf(observations),
                existing == null ? now : existing.createdAt(),
                existing == null ? 1 : existing.revision() + 1
        ));
    }

    /**
     * 返回指标记录的不可变快照；不存在返回 null。
     */
    public synchronized IndicatorRecord get(IndicatorKey key) {
        return records.get(key);
    }

    public synchronized int size() {
        return records.size();
    }

    /**
     * 仅供管理/测试：当前全部记录的快照。
     */
    public synchronized Map<IndicatorKey, IndicatorRecord> snapshot() {
        return Map.copyOf(records);
    }

    /**
     * 测试与示例数据加载用：清空存储。
     */
    public synchronized void clear() {
        records.clear();
    }

    /**
     * 单来源撤回接口：撤回某来源对某指标的支撑。
     */
    public synchronized int revokeSource(IndicatorKey key, String source) {
        IndicatorRecord existing = records.get(key);
        if (existing == null || !existing.observations().containsKey(source)) {
            return 0;
        }
        Map<String, SourceObservation> observations = new LinkedHashMap<>(existing.observations());
        observations.remove(source);
        if (observations.isEmpty()) {
            records.remove(key);
        } else {
            putRecord(key, observations, existing, clock.instant());
        }
        return 1;
    }
}
