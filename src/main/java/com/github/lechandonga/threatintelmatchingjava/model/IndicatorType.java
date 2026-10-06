package com.github.lechandonga.threatintelmatchingjava.model;

import java.util.Locale;

/**
 * Supported indicator types. A canonical type is shared by every feed so that
 * records describing the same observable from different sources can be merged.
 */
public enum IndicatorType {
    IPV4,
    DOMAIN,
    FILE_HASH;

    public static IndicatorType fromExternal(String raw) {
        if (raw == null) {
            return null;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT).replace('-', '_');
        return switch (value) {
            case "ip", "ipv4", "ip4", "ipv4_addr" -> IPV4;
            case "domain", "fqdn", "hostname" -> DOMAIN;
            case "hash", "file_hash", "filehash", "sha256", "md5", "sha1" -> FILE_HASH;
            default -> null;
        };
    }
}
