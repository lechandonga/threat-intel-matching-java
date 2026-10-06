package com.github.lechandonga.threatintelmatchingjava.normalize;

import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;
import com.github.lechandonga.threatintelmatchingjava.model.SourceRecord;
import com.github.lechandonga.threatintelmatchingjava.model.Verdict;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates raw feed rows and converts them to canonical {@link SourceRecord}s.
 * Every validation failure gets its own reason code, so callers can tell
 * missing fields, bad formats and out-of-range values apart.
 */
public class RecordNormalizer {

    private static final Pattern IPV4 = Pattern.compile(
            "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\\.(?!-)[a-z0-9-]{1,63}(?<!-))*\\.?$");
    private static final Set<String> SPECIAL_DOMAINS =
            Set.of("localhost", "local", "localhost.localdomain");

    public SourceRecord normalize(RawIndicatorRecord raw, Instant importedAt) throws ValidationException {
        requireText(raw.sourceId(), "SOURCE_ID_MISSING", "sourceId");
        requireText(raw.recordId(), "RECORD_ID_MISSING", "recordId");

        IndicatorType type = IndicatorType.fromExternal(raw.type());
        if (blank(raw.type())) {
            throw new ValidationException("TYPE_MISSING", "indicator type is missing");
        }
        if (type == null) {
            throw new ValidationException("TYPE_UNSUPPORTED", "unsupported indicator type: " + raw.type());
        }

        if (blank(raw.value())) {
            throw new ValidationException("VALUE_MISSING", "indicator value is missing");
        }
        String value = normalizeValue(type, raw.value().trim());

        Verdict verdict = Verdict.fromExternal(raw.verdict());
        if (blank(raw.verdict())) {
            throw new ValidationException("VERDICT_MISSING", "verdict is missing");
        }
        if (verdict == null) {
            throw new ValidationException("VERDICT_UNSUPPORTED", "unsupported verdict: " + raw.verdict());
        }

        double confidence = parseConfidence(raw.confidence());
        Instant observedAt = parseInstant(raw.observedAt());

        return new SourceRecord(
                raw.sourceId().trim().toLowerCase(Locale.ROOT),
                raw.recordId().trim(),
                type,
                value,
                verdict,
                confidence,
                observedAt,
                importedAt);
    }

    private void requireText(String value, String code, String field) throws ValidationException {
        if (blank(value)) {
            throw new ValidationException(code, field + " is missing or blank");
        }
    }

    private double parseConfidence(String raw) throws ValidationException {
        if (blank(raw)) {
            throw new ValidationException("CONFIDENCE_MISSING", "confidence is missing");
        }
        double value;
        try {
            value = Double.parseDouble(raw.trim());
        } catch (NumberFormatException e) {
            throw new ValidationException("CONFIDENCE_NOT_A_NUMBER",
                    "confidence must be a number between 0 and 1: " + raw);
        }
        if (Double.isNaN(value) || Double.isInfinite(value) || value < 0.0 || value > 1.0) {
            throw new ValidationException("CONFIDENCE_OUT_OF_RANGE",
                    "confidence must be within [0,1]: " + raw);
        }
        return value;
    }

    private Instant parseInstant(String raw) throws ValidationException {
        if (blank(raw)) {
            throw new ValidationException("TIMESTAMP_MISSING", "observedAt timestamp is missing");
        }
        try {
            return Instant.parse(raw.trim());
        } catch (DateTimeParseException e) {
            throw new ValidationException("TIMESTAMP_INVALID",
                    "observedAt must be an ISO-8601 instant (e.g. 2026-10-06T08:00:00Z): " + raw);
        }
    }

    private String normalizeValue(IndicatorType type, String raw) throws ValidationException {
        switch (type) {
            case IPV4 -> {
                if (!IPV4.matcher(raw).matches()) {
                    throw new ValidationException("IPV4_INVALID", "not a valid IPv4 address: " + raw);
                }
                return raw;
            }
            case DOMAIN -> {
                String lower = raw.toLowerCase(Locale.ROOT);
                String withoutTrailingDot = lower.endsWith(".") ? lower.substring(0, lower.length() - 1) : lower;
                if (!DOMAIN.matcher(withoutTrailingDot).matches()
                        || SPECIAL_DOMAINS.contains(withoutTrailingDot)
                        || !withoutTrailingDot.contains(".")) {
                    throw new ValidationException("DOMAIN_INVALID", "not a valid domain name: " + raw);
                }
                return withoutTrailingDot;
            }
            case FILE_HASH -> {
                String hex = raw.toLowerCase(Locale.ROOT);
                if (!hex.matches("[0-9a-f]+")) {
                    throw new ValidationException("HASH_INVALID_CHARACTERS",
                            "file hash must be hexadecimal: " + raw);
                }
                if (hex.length() != 32 && hex.length() != 40 && hex.length() != 64) {
                    throw new ValidationException("HASH_INVALID_LENGTH",
                            "file hash length must be 32 (MD5), 40 (SHA-1) or 64 (SHA-256): " + raw);
                }
                HexFormat.of().parseHex(hex);
                return hex;
            }
            default -> throw new ValidationException("TYPE_UNSUPPORTED", "unsupported indicator type: " + type);
        }
    }

    private boolean blank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
