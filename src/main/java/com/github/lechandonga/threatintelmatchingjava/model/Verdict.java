package com.github.lechandonga.threatintelmatchingjava.model;

import java.util.Locale;

/** Verdict claimed by a single source record. */
public enum Verdict {
    MALICIOUS,
    SUSPICIOUS,
    BENIGN;

    public static Verdict fromExternal(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "malicious", "malware", "bad", "threat" -> MALICIOUS;
            case "suspicious", "suspect", "questionable" -> SUSPICIOUS;
            case "benign", "clean", "safe", "harmless" -> BENIGN;
            default -> null;
        };
    }

    /** Severity used by the order-independent conflict tie breaker (higher wins). */
    public int severity() {
        return switch (this) {
            case MALICIOUS -> 3;
            case SUSPICIOUS -> 2;
            case BENIGN -> 1;
        };
    }
}
