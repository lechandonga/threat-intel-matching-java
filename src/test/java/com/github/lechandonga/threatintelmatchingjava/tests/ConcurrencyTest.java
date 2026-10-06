package com.github.lechandonga.threatintelmatchingjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.threatintelmatchingjava.feed.FeedParser;
import com.github.lechandonga.threatintelmatchingjava.feed.FlatFeedParser;
import com.github.lechandonga.threatintelmatchingjava.feed.StixFeedParser;
import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;
import com.github.lechandonga.threatintelmatchingjava.service.IntelStore;
import com.github.lechandonga.threatintelmatchingjava.service.VerdictEngine;
import com.github.lechandonga.threatintelmatchingjava.service.WhitelistService;
import com.github.lechandonga.threatintelmatchingjava.service.dto.VerdictResponse;
import com.github.lechandonga.threatintelmatchingjava.support.TestSupport;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务4：并发导入与查询。
 */
class ConcurrencyTest {

    @Test
    void parallelImportsFromDifferentSourcesProduceExactObservationCount() throws Exception {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);

        for (int i = 0; i < threads; i++) {
            String source = String.format("source-%02d", i);
            pool.submit(() -> {
                ready.countDown();
                await(start);
                service.importFeed("flat", TestSupport.flatDoc(source,
                        TestSupport.flatRecord("ip", "203.0.113.30", "malicious", 50 + (source.charAt(7) - '0'),
                                "2026-10-05T00:00:00Z", false)));
            });
        }
        ready.await();
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        VerdictResponse response = service.query("ip", "203.0.113.30");
        assertEquals(threads, response.sources().size(),
                "并发导入不能出现重复计数或来源丢失");
    }

    @Test
    void concurrentDuplicateImportsAreIdempotent() throws Exception {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        String doc = TestSupport.flatDoc("source-dup",
                TestSupport.flatRecord("ip", "203.0.113.31", "malicious", 90,
                        "2026-10-05T00:00:00Z", false));
        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger unchanged = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                await(start);
                ImportResult result = service.importFeed("flat", doc);
                accepted.addAndGet(result.accepted());
                unchanged.addAndGet(result.unchanged());
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        assertEquals(1, accepted.get(), "同一份数据并发重复导入只允许有一次生效");
        assertEquals(threads - 1, unchanged.get());
        assertEquals(1, service.query("ip", "203.0.113.31").sources().size());
    }

    @Test
    void queriesDuringImportsNeverSeeIntermediateState() throws Exception {
        IntelService service = TestSupport.newService(TestSupport.fixedClock(), 7, null);
        ExecutorService pool = Executors.newFixedThreadPool(6);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> failures = new ConcurrentLinkedQueue<>();
        AtomicInteger checks = new AtomicInteger();

        for (int sourceIndex = 0; sourceIndex < 4; sourceIndex++) {
            String source = "writer-" + sourceIndex;
            pool.submit(() -> {
                await(start);
                for (int round = 0; round < 50; round++) {
                    service.importFeed("flat", TestSupport.flatDoc(source,
                            TestSupport.flatRecord("ip", "203.0.113.32", "malicious", 90,
                                    "2026-10-05T00:00:00Z", round % 25 == 24)));
                }
            });
        }
        for (int reader = 0; reader < 2; reader++) {
            pool.submit(() -> {
                await(start);
                for (int i = 0; i < 500; i++) {
                    VerdictResponse response = service.query("ip", "203.0.113.32");
                    checks.incrementAndGet();
                    long distinctSources = response.sources().stream().map(s -> s.source()).distinct().count();
                    if (distinctSources != response.sources().size()) {
                        failures.add("同一响应中来源重复，出现中间状态");
                    }
                    if (response.sources().size() > 4) {
                        failures.add("来源数超过写入者数量: " + response.sources().size());
                    }
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        assertTrue(checks.get() > 0);
        assertTrue(failures.isEmpty(), "并发读不应看到重复/中间状态: " + failures);
    }

    @Test
    void storeExposesConsistentSnapshotUnderMixedWorkload() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        List<FeedParser> parsers = List.of(new StixFeedParser(mapper), new FlatFeedParser(mapper));
        IntelStore store = new IntelStore(TestSupport.fixedClock());
        WhitelistService whitelist = new WhitelistService(null);
        VerdictEngine engine = new VerdictEngine(TestSupport.fixedClock(), 7);
        IntelService service = new IntelService(parsers, store, whitelist, engine);

        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < 4; i++) {
            int index = i;
            pool.submit(() -> {
                await(start);
                for (int round = 0; round < 100; round++) {
                    service.importFeed("flat", TestSupport.flatDoc("src-" + index,
                            TestSupport.flatRecord("ip", "203.0.113." + (40 + index),
                                    "suspicious", 60, "2026-10-05T00:00:00Z", false)));
                }
            });
        }
        ConcurrentLinkedQueue<RuntimeException> errors = new ConcurrentLinkedQueue<>();
        pool.submit(() -> {
            await(start);
            for (int i = 0; i < 1000; i++) {
                try {
                    store.snapshot().forEach((key, record) -> {
                        if (record.observations().isEmpty()) {
                            throw new IllegalStateException("快照中出现空来源指标");
                        }
                    });
                } catch (RuntimeException e) {
                    errors.add(e);
                }
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(errors.isEmpty(), errors.toString());
        assertEquals(4, store.size());
        assertEquals(Instant.parse("2026-10-06T00:00:00Z"),
                service.query("ip", "203.0.113.40").evaluatedAt());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}
