package com.github.lechandonga.threatintelmatchingjava.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatintelmatchingjava.feed.FeedParser;
import com.github.lechandonga.threatintelmatchingjava.feed.FlatFeedParser;
import com.github.lechandonga.threatintelmatchingjava.feed.StixFeedParser;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;
import com.github.lechandonga.threatintelmatchingjava.service.IntelStore;
import com.github.lechandonga.threatintelmatchingjava.service.VerdictEngine;
import com.github.lechandonga.threatintelmatchingjava.service.WhitelistService;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

/**
 * 测试装配：纯手工 new，不启动 Spring。
 */
public final class TestSupport {

    public static final Instant NOW = Instant.parse("2026-10-06T00:00:00Z");

    private TestSupport() {
    }

    public static Clock fixedClock() {
        return Clock.fixed(NOW, ZoneOffset.UTC);
    }

    public static IntelService newService(Clock clock, double halfLifeDays, Path whitelistFile) {
        ObjectMapper mapper = new ObjectMapper();
        List<FeedParser> parsers = List.of(new StixFeedParser(mapper), new FlatFeedParser(mapper));
        IntelStore store = new IntelStore(clock);
        WhitelistService whitelist = new WhitelistService(whitelistFile);
        VerdictEngine engine = new VerdictEngine(clock, halfLifeDays);
        return new IntelService(parsers, store, whitelist, engine);
    }

    public static String flatRecord(String type, String value, String disposition,
                                   int confidence, String observedAt, boolean revoked) {
        String revokedPart = revoked ? ",\"revoked\":true" : "";
        return "{\"indicator_type\":\"" + type + "\",\"value\":\"" + value
                + "\",\"disposition\":\"" + disposition + "\",\"confidence\":" + confidence
                + ",\"observed_at\":\"" + observedAt + "\"" + revokedPart + "}";
    }

    public static String flatDoc(String source, String... records) {
        return "{\"source\":\"" + source + "\",\"records\":[" + String.join(",", records) + "]}";
    }
}
