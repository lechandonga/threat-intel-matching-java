package com.github.lechandonga.threatintelmatchingjava.store;

import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;
import com.github.lechandonga.threatintelmatchingjava.model.SourceRecord;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Concurrent in-memory store of merged indicators.
 *
 * <p>An indicator is keyed by {@code (type, canonical value)} and holds every
 * supporting source record. All mutation of one indicator happens atomically
 * inside {@link ConcurrentHashMap#compute}, so concurrent imports, withdrawals
 * and queries can never duplicate counts, lose updates or observe a
 * half-merged state. Reads return immutable snapshots.
 */
@org.springframework.stereotype.Component
public class IndicatorStore {

    public record IndicatorSnapshot(IndicatorType type, String value, List<SourceRecord> records) {
    }

    public record UpsertOutcome(boolean createdIndicator, boolean addedSource, boolean unchanged) {
    }

    public record WithdrawOutcome(boolean recordExisted, boolean indicatorRemoved) {
    }

    private final ConcurrentHashMap<String, Map<String, SourceRecord>> indicators = new ConcurrentHashMap<>();

    public static String key(IndicatorType type, String value) {
        return type.name() + "\u0000" + value;
    }

    /**
     * Insert or update one source record. Identical re-import is a no-op
     * ({@code unchanged == true}).
     */
    public UpsertOutcome upsert(SourceRecord incoming) {
        String indicatorKey = key(incoming.type(), incoming.value());
        UpsertOutcome[] outcome = new UpsertOutcome[1];
        indicators.compute(indicatorKey, (key, recordsByRecordKey) -> {
            boolean created = recordsByRecordKey == null;
            Map<String, SourceRecord> records = created ? new HashMap<>() : recordsByRecordKey;
            SourceRecord existing = records.get(incoming.recordKey());
            boolean unchanged = existing != null && equalsRecord(existing, incoming);
            boolean addedSource = existing == null
                    && records.values().stream().noneMatch(r -> r.sourceId().equals(incoming.sourceId()));
            if (!unchanged) {
                records.put(incoming.recordKey(), incoming);
            }
            outcome[0] = new UpsertOutcome(created, addedSource, unchanged);
            return records;
        });
        return outcome[0];
    }

    /** Withdraw one source record. The indicator disappears when nothing supports it. */
    public WithdrawOutcome withdraw(String sourceId, String recordId) {
        String recordKey = sourceId + "\u0000" + recordId;
        WithdrawOutcome[] outcome = new WithdrawOutcome[1];
        for (Map.Entry<String, Map<String, SourceRecord>> entry : indicators.entrySet()) {
            String indicatorKey = entry.getKey();
            if (!entry.getValue().containsKey(recordKey)) {
                continue;
            }
            indicators.compute(indicatorKey, (key, records) -> {
                if (records == null || !records.containsKey(recordKey)) {
                    outcome[0] = new WithdrawOutcome(false, false);
                    return records;
                }
                records.remove(recordKey);
                if (records.isEmpty()) {
                    outcome[0] = new WithdrawOutcome(true, true);
                    return null;
                }
                outcome[0] = new WithdrawOutcome(true, false);
                return records;
            });
            return outcome[0];
        }
        return new WithdrawOutcome(false, false);
    }

    /** Withdraw every record of a source. Returns removed record keys and removed indicator keys. */
    public BatchWithdraw withdrawSource(String sourceId) {
        List<String> removedRecordKeys = new ArrayList<>();
        List<String> removedIndicatorKeys = new ArrayList<>();
        for (String indicatorKey : List.copyOf(indicators.keySet())) {
            indicators.compute(indicatorKey, (key, records) -> {
                if (records == null) {
                    return null;
                }
                boolean removed = records.entrySet().removeIf(e -> e.getKey().startsWith(sourceId + "\u0000"));
                if (removed) {
                    for (String rk : records.keySet()) {
                        if (rk.startsWith(sourceId + "\u0000")) {
                            removedRecordKeys.add(rk);
                        }
                    }
                }
                if (removed) {
                    records.keySet().removeIf(rk -> {
                        if (rk.startsWith(sourceId + "\u0000")) {
                            removedRecordKeys.add(rk);
                            return true;
                        }
                        return false;
                    });
                }
                if (records.isEmpty()) {
                    removedIndicatorKeys.add(indicatorKey);
                    return null;
                }
                return records;
            });
        }
        return new BatchWithdraw(removedRecordKeys.size(), removedIndicatorKeys.size());
    }

    public record BatchWithdraw(int removedRecords, int removedIndicators) {
    }

    public Optional<IndicatorSnapshot> get(IndicatorType type, String value) {
        Map<String, SourceRecord> records = indicators.get(key(type, value));
        if (records == null) {
            return Optional.empty();
        }
        synchronized (records) {
            return Optional.of(new IndicatorSnapshot(type, value, List.copyOf(records.values())));
        }
    }

    public List<IndicatorSnapshot> all() {
        List<IndicatorSnapshot> snapshots = new ArrayList<>();
        for (Map.Entry<String, Map<String, SourceRecord>> entry : indicators.entrySet()) {
            Map<String, SourceRecord> records = entry.getValue();
            synchronized (records) {
                if (!records.isEmpty()) {
                    String[] parts = entry.getKey().split("\u0000", 2);
                    snapshots.add(new IndicatorSnapshot(
                            IndicatorType.valueOf(parts[0]), parts[1], List.copyOf(records.values())));
                }
            }
        }
        return snapshots;
    }

    public int size() {
        return indicators.size();
    }

    private boolean equalsRecord(SourceRecord a, SourceRecord b) {
        return a.sourceId().equals(b.sourceId())
                && a.recordId().equals(b.recordId())
                && a.type() == b.type()
                && a.value().equals(b.value())
                && a.verdict() == b.verdict()
                && Double.compare(a.confidence(), b.confidence()) == 0
                && a.observedAt().equals(b.observedAt());
    }
}
