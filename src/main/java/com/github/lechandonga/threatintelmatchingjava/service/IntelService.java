package com.github.lechandonga.threatintelmatchingjava.service;

import com.github.lechandonga.threatintelmatchingjava.feed.FeedParser;
import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorKey;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorRecord;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;
import com.github.lechandonga.threatintelmatchingjava.model.SourceObservation;
import com.github.lechandonga.threatintelmatchingjava.model.Verdict;
import com.github.lechandonga.threatintelmatchingjava.normalize.IndicatorNormalizer;
import com.github.lechandonga.threatintelmatchingjava.service.dto.SourceView;
import com.github.lechandonga.threatintelmatchingjava.service.dto.VerdictResponse;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 对外的顶层服务：解析 → 合并/撤回 → 判定查询。
 */
public class IntelService {

    private final Map<String, FeedParser> parsers;
    private final IntelStore store;
    private final WhitelistService whitelist;
    private final VerdictEngine engine;

    public IntelService(List<FeedParser> parserList, IntelStore store,
                        WhitelistService whitelist, VerdictEngine engine) {
        this.parsers = parserList.stream().collect(java.util.stream.Collectors
                .toUnmodifiableMap(FeedParser::format, p -> p));
        this.store = store;
        this.whitelist = whitelist;
        this.engine = engine;
    }

    public ImportResult importFeed(String format, String document) {
        FeedParser parser = parsers.get(format);
        if (parser == null) {
            throw new IllegalArgumentException("不支持的来源格式: " + format + "（支持: " + parsers.keySet() + "）");
        }
        FeedParser.ParseOutcome outcome = parser.parse(document);
        return store.apply(outcome.entries(), outcome.rejected());
    }

    /**
     * 判定查询。
     *
     * @param typeRaw 类型字符串：ip/domain/md5/sha1/sha256/hash
     * @param valueRaw 原始值，会先归一化
     */
    public VerdictResponse query(String typeRaw, String valueRaw) {
        IndicatorType type = WhitelistService.parseType(typeRaw.trim());
        if (type == null) {
            throw new IllegalArgumentException("不支持的指标类型: " + typeRaw);
        }
        String value = IndicatorNormalizer.normalize(type, valueRaw);
        if (value == null && typeRaw.trim().equalsIgnoreCase("hash")) {
            type = WhitelistService.guessType(valueRaw.trim());
            value = type == null ? null : IndicatorNormalizer.normalize(type, valueRaw);
        }
        if (value == null) {
            throw new IllegalArgumentException("指标值非法: " + valueRaw);
        }

        IndicatorKey key = new IndicatorKey(type, value);
        IndicatorRecord record = store.get(key);
        Instant now = engine.clock().instant();
        boolean whitelisted = whitelist.contains(key);

        if (record == null) {
            return new VerdictResponse(type.name(), value, Verdict.HARMLESS.name(),
                    whitelisted, false,
                    whitelisted ? "WHITELIST_PRIORITY" : "NO_INTEL",
                    null, engine.halfLifeDays(), now, List.of());
        }

        SourceObservation winner = engine.adjudicate(record, now);
        Verdict verdict = whitelisted ? Verdict.HARMLESS : engine.toVerdict(winner, now);
        String rule = whitelisted
                ? "WHITELIST_PRIORITY"
                : "MAX_DECAYED_CONFIDENCE_THEN_WEIGHT_THEN_SOURCE_NAME";

        List<SourceView> views = new ArrayList<>();
        for (SourceObservation observation : record.observations().values().stream()
                .sorted(java.util.Comparator.comparing(SourceObservation::source)).toList()) {
            double decayed = round(engine.effectiveConfidence(observation, now));
            views.add(new SourceView(
                    observation.source(),
                    observation.disposition().name(),
                    observation.rawConfidence(),
                    decayed,
                    round(observation.disposition().weight() * decayed),
                    observation.observedAt(),
                    observation.firstSeen(),
                    observation.lastSeen(),
                    observation.revision(),
                    observation.source().equals(winner.source())
            ));
        }

        return new VerdictResponse(type.name(), value, verdict.name(), whitelisted, true,
                rule, winner.source(), engine.halfLifeDays(), now, views);
    }

    private static double round(double v) {
        return Math.round(v * 10000.0) / 10000.0;
    }
}
