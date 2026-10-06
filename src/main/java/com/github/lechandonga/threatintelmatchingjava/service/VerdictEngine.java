package com.github.lechandonga.threatintelmatchingjava.service;

import com.github.lechandonga.threatintelmatchingjava.model.Disposition;
import com.github.lechandonga.threatintelmatchingjava.model.IndicatorRecord;
import com.github.lechandonga.threatintelmatchingjava.model.SourceObservation;
import com.github.lechandonga.threatintelmatchingjava.model.Verdict;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 裁决引擎：置信度时间衰减 + 来源冲突的固定规则裁决。
 *
 * <p>衰减：effectiveConfidence = rawConfidence/100 * 0.5^(ageDays/halfLifeDays)，
 * 默认半衰期 7 天。评分 score = disposition.weight * effectiveConfidence。
 *
 * <p>与导入顺序无关的固定裁决规则：
 * <ol>
 *   <li>白名单优先：命中白名单直接 HARMLESS，依据中仍列出原始来源。</li>
 *   <li>取有效置信度最大的来源（effectiveConfidence）；平分时按结论权重
 *       （malicious &gt; suspicious &gt; benign）裁决，再平分按来源标识字典序固定。</li>
 *   <li>中选结论权重 &ge;0.75 → MALICIOUS；&ge;0.25 → SUSPICIOUS；其余 HARMLESS。</li>
 * </ol>
 */
public class VerdictEngine {

    private final Clock clock;
    private final double halfLifeDays;

    public VerdictEngine(Clock clock, double halfLifeDays) {
        this.clock = clock;
        this.halfLifeDays = halfLifeDays;
    }

    public double effectiveConfidence(SourceObservation observation, Instant now) {
        long ageSeconds = Duration.between(observation.observedAt(), now).getSeconds();
        double ageDays = Math.max(0.0, ageSeconds / 86_400.0);
        double base = observation.rawConfidence() / 100.0;
        return base * Math.pow(0.5, ageDays / halfLifeDays);
    }

    /**
     * 选出裁决中选来源（确定性排序，与导入顺序无关）。
     */
    public SourceObservation adjudicate(IndicatorRecord record, Instant now) {
        List<SourceObservation> observations = new ArrayList<>(record.observations().values());
        observations.sort(Comparator
                .comparingDouble((SourceObservation o) -> effectiveConfidence(o, now)).reversed()
                .thenComparing(o -> -o.disposition().weight())
                .thenComparing(SourceObservation::source));
        return observations.get(0);
    }

    public Verdict toVerdict(SourceObservation winner, Instant now) {
        double score = winner.disposition().weight() * effectiveConfidence(winner, now);
        if (winner.disposition() == Disposition.MALICIOUS && score >= 0.75) {
            return Verdict.MALICIOUS;
        }
        if (score >= 0.25) {
            return Verdict.SUSPICIOUS;
        }
        return Verdict.HARMLESS;
    }

    public Clock clock() {
        return clock;
    }

    public double halfLifeDays() {
        return halfLifeDays;
    }
}
