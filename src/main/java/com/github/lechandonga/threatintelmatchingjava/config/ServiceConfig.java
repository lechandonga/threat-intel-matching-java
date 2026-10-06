package com.github.lechandonga.threatintelmatchingjava.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatintelmatchingjava.feed.FeedParser;
import com.github.lechandonga.threatintelmatchingjava.feed.FlatFeedParser;
import com.github.lechandonga.threatintelmatchingjava.feed.StixFeedParser;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;
import com.github.lechandonga.threatintelmatchingjava.service.IntelStore;
import com.github.lechandonga.threatintelmatchingjava.service.VerdictEngine;
import com.github.lechandonga.threatintelmatchingjava.service.WhitelistService;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;

@Configuration
public class ServiceConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public IntelStore intelStore(Clock clock) {
        return new IntelStore(clock);
    }

    @Bean
    public VerdictEngine verdictEngine(Clock clock,
                                       @Value("${intel.confidence.half-life-days:7}") double halfLifeDays) {
        return new VerdictEngine(clock, halfLifeDays);
    }

    @Bean
    public WhitelistService whitelistService(
            @Value("${intel.whitelist.file:data/whitelist.txt}") String whitelistFile) {
        return new WhitelistService(Path.of(whitelistFile));
    }

    @Bean
    public List<FeedParser> feedParsers(ObjectMapper mapper) {
        return List.of(new StixFeedParser(mapper), new FlatFeedParser(mapper));
    }

    @Bean
    public IntelService intelService(List<FeedParser> parsers, IntelStore store,
                                     WhitelistService whitelist, VerdictEngine engine) {
        return new IntelService(parsers, store, whitelist, engine);
    }
}
