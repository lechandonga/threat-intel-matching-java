package com.github.lechandonga.threatintelmatchingjava.feed;

import com.github.lechandonga.threatintelmatchingjava.model.Disposition;

final class DispositionMapping {

    private DispositionMapping() {
    }

    static Disposition fromFlat(String raw) {
        return switch (raw.trim().toLowerCase()) {
            case "malicious", "malware", "bad", "1" -> Disposition.MALICIOUS;
            case "suspicious", "suspect", "2" -> Disposition.SUSPICIOUS;
            case "benign", "clean", "harmless", "0" -> Disposition.BENIGN;
            default -> null;
        };
    }

    static Disposition fromStixLabels(Iterable<String> labels) {
        boolean suspicious = false;
        for (String label : labels) {
            String normalized = label == null ? "" : label.trim().toLowerCase();
            if (normalized.contains("benign") || normalized.contains("whitelist")
                    || normalized.contains("allowlist")) {
                return Disposition.BENIGN;
            }
            if (normalized.contains("malicious") || normalized.contains("malware")
                    || normalized.contains("c2") || normalized.contains("ransomware")) {
                return Disposition.MALICIOUS;
            }
            if (normalized.contains("suspicious") || normalized.contains("unknown")) {
                suspicious = true;
            }
        }
        return suspicious ? Disposition.SUSPICIOUS : null;
    }
}
