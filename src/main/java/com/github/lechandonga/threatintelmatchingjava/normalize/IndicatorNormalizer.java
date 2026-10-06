package com.github.lechandonga.threatintelmatchingjava.normalize;

import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * 指标值归一化与校验。
 * 归一化后的值同时作为存储键的一部分，保证不同来源的同一指标可以合并。
 */
public final class IndicatorNormalizer {

    private static final String HEX = "0123456789abcdef";
    private static final int MAX_DOMAIN_LENGTH = 253;
    private static final int MAX_LABEL_LENGTH = 63;

    private IndicatorNormalizer() {
    }

    public static Instant parseTime(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(raw.trim());
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /**
     * 归一化并校验，返回 null 表示不合法。
     */
    public static String normalize(IndicatorType type, String raw) {
        if (raw == null) {
            return null;
        }
        String value = raw.trim();
        if (value.isEmpty()) {
            return null;
        }
        return switch (type) {
            case IP -> normalizeIp(value);
            case DOMAIN -> normalizeDomain(value);
            case HASH_MD5, HASH_SHA1, HASH_SHA256 -> normalizeHash(type, value);
        };
    }

    private static String normalizeIp(String value) {
        if (value.chars().filter(c -> c == ':').count() > 0) {
            if (value.indexOf('.') >= 0 && !value.startsWith("::ffff:")) {
                // 不接受裸 IPv4 映射写法（如 ::ffff:1.2.3.4）以外的混合形态
                if (value.lastIndexOf(':') < value.lastIndexOf('.')) {
                    return null;
                }
            }
        }
        try {
            byte[] addr = InetAddress.getByName(value).getAddress();
            boolean v6 = addr.length == 16;
            String canonical = InetAddress.getByAddress(addr).getHostAddress();
            // getByName 对非法串可能抛异常或做主机名解析，这里用格式复核防止误判主机名
            if (v6) {
                return looksLikeIpv6(value) ? canonical : null;
            }
            return looksLikeIpv4(value) ? canonical : null;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean looksLikeIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.chars().allMatch(Character::isDigit)) {
                return false;
            }
            int n = Integer.parseInt(part);
            if (n > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean looksLikeIpv6(String value) {
        String head = value;
        int pct = head.indexOf('%');
        if (pct >= 0) {
            head = head.substring(0, pct);
        }
        if (head.indexOf(':') < 0) {
            return false;
        }
        for (int i = 0; i < head.length(); i++) {
            char c = head.charAt(i);
            if (c != ':' && HEX.indexOf(Character.toLowerCase(c)) < 0 && c != '.') {
                return false;
            }
        }
        long groups = head.chars().filter(c -> c == ':').count();
        long doubleColons = countOccurrences(head, "::");
        if (doubleColons > 1) {
            return false;
        }
        if (doubleColons == 0 && groups != 7) {
            return false;
        }
        return true;
    }

    private static long countOccurrences(String text, String token) {
        long count = 0;
        int idx = 0;
        while ((idx = text.indexOf(token, idx)) >= 0) {
            count++;
            idx += token.length();
        }
        return count;
    }

    private static String normalizeDomain(String raw) {
        String value = raw;
        if (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }
        value = value.toLowerCase();
        if (value.isEmpty() || value.length() > MAX_DOMAIN_LENGTH || value.startsWith(".") || value.contains("..")) {
            return null;
        }
        String[] labels = value.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > MAX_LABEL_LENGTH) {
                return null;
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9')
                        || c == '-';
                if (!ok) {
                    return null;
                }
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                return null;
            }
        }
        return value;
    }

    private static String normalizeHash(IndicatorType type, String raw) {
        String value = raw.toLowerCase();
        if (!value.chars().allMatch(c -> HEX.indexOf((char) c) >= 0)) {
            return null;
        }
        IndicatorType inferred = IndicatorType.hashTypeByLength(value.length());
        if (inferred == null || inferred != type) {
            return null;
        }
        return value;
    }
}
