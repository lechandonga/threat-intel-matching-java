package com.github.lechandonga.threatintelmatchingjava.model;

import java.time.Instant;

/**
 * One normalized record originating from a single feed. Two imports with the
 * same {@code (sourceId, recordId)} describe the same record and are therefore
 * idempotent: re-importing identical data changes nothing.
 */
public record SourceRecord(
        String sourceId,
        String recordId,
        IndicatorType type,
        String value,
        Verdict verdict,
        double confidence,
        Instant observedAt,
        Instant importedAt) {

    /** Stable identity of this record inside its source. */
    public String recordKey() {
        return sourceId + "\u0000" + recordId;
    }
}
