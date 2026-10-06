package com.github.lechandonga.threatintelmatchingjava.model;

/** A rejected raw record together with a machine-readable, distinguishable reason. */
public record ImportRejection(
        int line,
        String rawRecord,
        String reasonCode,
        String reason) {
}
