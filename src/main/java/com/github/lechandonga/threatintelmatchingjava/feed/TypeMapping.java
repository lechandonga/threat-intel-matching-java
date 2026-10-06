package com.github.lechandonga.threatintelmatchingjava.feed;

import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;

final class TypeMapping {

    private static final String HEX = "0123456789abcdef";

    private TypeMapping() {
    }

    static IndicatorType fromFlat(String raw) {
        return switch (raw.toLowerCase().replace('_', '-')) {
            case "ip", "ipv4", "ipv6" -> IndicatorType.IP;
            case "domain", "hostname" -> IndicatorType.DOMAIN;
            case "md5" -> IndicatorType.HASH_MD5;
            case "sha1", "sha-1" -> IndicatorType.HASH_SHA1;
            case "sha256", "sha-256" -> IndicatorType.HASH_SHA256;
            case "hash" -> IndicatorType.HASH_MD5;
            default -> null;
        };
    }

    static IndicatorType inferHashType(String rawValue) {
        if (rawValue == null) {
            return null;
        }
        String hex = rawValue.trim().toLowerCase();
        if (hex.isEmpty() || !hex.chars().allMatch(c -> HEX.indexOf((char) c) >= 0)) {
            return null;
        }
        return IndicatorType.hashTypeByLength(hex.length());
    }
}
