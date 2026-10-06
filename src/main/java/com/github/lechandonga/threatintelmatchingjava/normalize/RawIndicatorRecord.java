package com.github.lechandonga.threatintelmatchingjava.normalize;

import java.time.Instant;

/** Fields as extracted from a feed before validation/normalization. */
public record RawIndicatorRecord(
        String sourceId,
        String recordId,
        String type,
        String value,
        String verdict,
        String confidence,
        String observedAt) {

    public String oneLine() {
        return "recordId=" + recordId + ", type=" + type + ", value=" + value
                + ", verdict=" + verdict + ", confidence=" + confidence
                + ", observedAt=" + observedAt;
    }
}
