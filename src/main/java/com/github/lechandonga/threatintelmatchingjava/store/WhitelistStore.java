package com.github.lechandonga.threatintelmatchingjava.store;

import com.github.lechandonga.threatintelmatchingjava.model.IndicatorType;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Whitelist entries that always override a malicious verdict. */
@Component
public class WhitelistStore {

    public record WhitelistEntry(IndicatorType type, String value, String reason) {
    }

    private final Map<String, WhitelistEntry> entries = new ConcurrentHashMap<>();

    public void put(IndicatorType type, String value, String reason) {
        entries.put(IndicatorStore.key(type, value),
                new WhitelistEntry(type, value, reason == null ? "" : reason));
    }

    public Optional<WhitelistEntry> lookup(IndicatorType type, String value) {
        return Optional.ofNullable(entries.get(IndicatorStore.key(type, value)));
    }

    public int size() {
        return entries.size();
    }
}
