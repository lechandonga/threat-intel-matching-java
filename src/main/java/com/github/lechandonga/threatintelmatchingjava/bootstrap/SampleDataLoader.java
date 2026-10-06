package com.github.lechandonga.threatintelmatchingjava.bootstrap;

import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 启动时从本地 data/samples 目录加载示例情报，纯本地、无外部服务依赖。
 */
@Component
public class SampleDataLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SampleDataLoader.class);

    private final IntelService intelService;
    private final boolean loadOnStartup;

    public SampleDataLoader(IntelService intelService,
                            @Value("${intel.sample.load-on-startup:true}") boolean loadOnStartup) {
        this.intelService = intelService;
        this.loadOnStartup = loadOnStartup;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (!loadOnStartup) {
            log.info("[sample] 已禁用启动示例加载 (intel.sample.load-on-startup=false)");
            return;
        }
        load("stix", Path.of("data/samples/stix-bundle.json"));
        load("flat", Path.of("data/samples/flat-feed.json"));
    }

    private void load(String format, Path path) throws Exception {
        if (!Files.exists(path)) {
            log.info("[sample] 示例文件不存在，跳过: {}", path);
            return;
        }
        String document = Files.readString(path, StandardCharsets.UTF_8);
        ImportResult result = intelService.importFeed(format, document);
        log.info("[sample] 加载 {} ({})：接受/更新={} 幂等跳过={} 撤回={} 撤回不存在={} 拒绝={}",
                format, path,
                result.accepted(), result.unchanged(), result.revoked(),
                result.alreadyAbsent(), result.rejected().size());
        result.rejected().forEach(rejected -> log.warn("[sample] 拒绝记录 #{}：{} - {}",
                rejected.index(), rejected.reason(), rejected.detail()));
    }
}
