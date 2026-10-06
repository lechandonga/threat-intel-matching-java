package com.github.lechandonga.threatintelmatchingjava.model;

import java.util.List;

/** A merged view of one indicator across every source currently supporting it. */
public record MergedIndicator(
        IndicatorType type,
        String value,
        List<SourceRecord> sources) {
}
