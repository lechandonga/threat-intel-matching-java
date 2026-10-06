package com.github.lechandonga.threatintelmatchingjava.feed;

import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 解析本服务支持的 STIX 2 indicator pattern 子集：
 * [ipv4-addr:value = '1.2.3.4']、[ipv6-addr:value='...']、
 * [domain-name:value = 'evil.example']、
 * [file:hashes.'SHA-256' = '...'] 以及 [file:hashes.MD5='...'] 等。
 */
final class StixPattern {

    private static final Pattern IPV4 = Pattern.compile(
            "\\[\\s*ipv4-addr\\s*:\\s*value\\s*=\\s*'([^']+)'\\s*\\]");
    private static final Pattern IPV6 = Pattern.compile(
            "\\[\\s*ipv6-addr\\s*:\\s*value\\s*=\\s*'([^']+)'\\s*\\]");
    private static final Pattern DOMAIN = Pattern.compile(
            "\\[\\s*domain-name\\s*:\\s*value\\s*=\\s*'([^']+)'\\s*\\]");
    private static final Pattern FILE_HASH = Pattern.compile(
            "\\[\\s*file\\s*:\\s*hashes\\s*[.:]\\s*'?\\s*([A-Za-z0-9-]+)\\s*'?\\s*=\\s*'([^']+)'\\s*\\]");

    record Extracted(IndicatorType type, String value) {
    }

    private StixPattern() {
    }

    static Extracted extract(String expression) {
        if (expression == null || expression.isBlank()) {
            return null;
        }
        Matcher hashMatcher = FILE_HASH.matcher(expression);
        if (hashMatcher.matches()) {
            IndicatorType type = switch (hashMatcher.group(1).toUpperCase().replace("_", "-")) {
                case "MD5" -> IndicatorType.HASH_MD5;
                case "SHA-1", "SHA1" -> IndicatorType.HASH_SHA1;
                case "SHA-256", "SHA256" -> IndicatorType.HASH_SHA256;
                default -> null;
            };
            return type == null ? null : new Extracted(type, hashMatcher.group(2));
        }
        Matcher v4 = IPV4.matcher(expression);
        if (v4.matches()) {
            return new Extracted(IndicatorType.IP, v4.group(1));
        }
        Matcher v6 = IPV6.matcher(expression);
        if (v6.matches()) {
            return new Extracted(IndicatorType.IP, v6.group(1));
        }
        Matcher domain = DOMAIN.matcher(expression);
        if (domain.matches()) {
            return new Extracted(IndicatorType.DOMAIN, domain.group(1));
        }
        return null;
    }
}
