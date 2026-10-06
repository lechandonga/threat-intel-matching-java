package com.github.lechandonga.threatintelmatchingjava.service;

import com.github.lechandonga.threatintelmatchingjava.model.IndicatorKey;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;
import com.github.lechandonga.threatintelmatchingjava.normalize.IndicatorNormalizer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 白名单服务。白名单对象即使被情报命中也优先判为无害。
 * 默认从 classpath 之外的本地文件 data/whitelist.txt 加载（每行一个
 * "类型,值" 或直接写 IP/域名，# 开头为注释），并支持运行时追加。
 */
public class WhitelistService {

    private final Set<IndicatorKey> whitelist = new LinkedHashSet<>();
    private final Path file;

    public WhitelistService(Path file) {
        this.file = file;
        load();
    }

    private void load() {
        if (file == null || !Files.exists(file)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                add(trimmed);
            }
        } catch (IOException e) {
            throw new IllegalStateException("加载白名单失败: " + file, e);
        }
    }

    /**
     * 添加一条白名单，支持 "ip,1.2.3.4"、"domain,example.com"、
     * "hash,&lt;hex&gt;" 或直接给 IP/域名/哈希值。
     *
     * @return 归一化后的键；值非法返回 null
     */
    public synchronized IndicatorKey add(String spec) {
        String[] parts = spec.trim().split(",", 2);
        IndicatorType type;
        String raw;
        if (parts.length == 2) {
            type = parseType(parts[0].trim());
            raw = parts[1].trim();
            if (type == null) {
                return null;
            }
        } else {
            raw = parts[0].trim();
            type = guessType(raw);
            if (type == null) {
                return null;
            }
        }
        String normalized = IndicatorNormalizer.normalize(type, raw);
        if (normalized == null) {
            return null;
        }
        whitelist.add(new IndicatorKey(type, normalized));
        return new IndicatorKey(type, normalized);
    }

    public synchronized boolean contains(IndicatorKey key) {
        return whitelist.contains(key);
    }

    public synchronized Set<IndicatorKey> all() {
        return new LinkedHashSet<>(whitelist);
    }

    static IndicatorType parseType(String raw) {
        return switch (raw.toLowerCase()) {
            case "ip" -> IndicatorType.IP;
            case "domain" -> IndicatorType.DOMAIN;
            case "md5" -> IndicatorType.HASH_MD5;
            case "sha1" -> IndicatorType.HASH_SHA1;
            case "sha256" -> IndicatorType.HASH_SHA256;
            case "hash" -> IndicatorType.HASH_MD5;
            default -> null;
        };
    }

    static IndicatorType guessType(String raw) {
        if (IndicatorNormalizer.normalize(IndicatorType.IP, raw) != null) {
            return IndicatorType.IP;
        }
        if (IndicatorNormalizer.normalize(IndicatorType.DOMAIN, raw) != null) {
            return IndicatorType.DOMAIN;
        }
        String hex = raw.toLowerCase();
        if (hex.chars().allMatch(c -> "0123456789abcdef".indexOf((char) c) >= 0)) {
            IndicatorType hashType = IndicatorType.hashTypeByLength(hex.length());
            if (hashType != null) {
                return hashType;
            }
        }
        return null;
    }

    /**
     * 测试专用。
     */
    synchronized void clear() {
        whitelist.clear();
    }
}
