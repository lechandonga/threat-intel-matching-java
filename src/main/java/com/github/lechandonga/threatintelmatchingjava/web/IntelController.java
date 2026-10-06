package com.github.lechandonga.threatintelmatchingjava.web;

import com.github.lechandonga.threatintelmatchingjava.model.ImportResult;
import com.github.lechandonga.threatintelmatchingjava.service.IntelService;
import com.github.lechandonga.threatintelmatchingjava.service.WhitelistService;
import com.github.lechandonga.threatintelmatchingjava.service.dto.VerdictResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/intel")
public class IntelController {

    private final IntelService intelService;
    private final WhitelistService whitelist;

    public IntelController(IntelService intelService, WhitelistService whitelist) {
        this.intelService = intelService;
        this.whitelist = whitelist;
    }

    /**
     * 导入情报批次。format=stix 或 flat。
     */
    @PostMapping("/import/{format}")
    public ImportResult importFeed(@PathVariable String format, @RequestBody String document) {
        return intelService.importFeed(format, document);
    }

    /**
     * 判定查询，例如 /api/intel/query/ip/203.0.113.10。
     */
    @GetMapping("/query/{type}/{value:.+}")
    public VerdictResponse query(@PathVariable String type, @PathVariable String value) {
        return intelService.query(type, value);
    }

    /**
     * 查询参数形式，便于哈希查询：/api/intel/query?type=sha256&value=...
     */
    @GetMapping("/query")
    public VerdictResponse queryParam(@RequestParam String type, @RequestParam String value) {
        return intelService.query(type, value);
    }

    @GetMapping("/whitelist")
    public List<Map<String, String>> listWhitelist() {
        return whitelist.all().stream()
                .map(key -> Map.of("type", key.type().name(), "value", key.value()))
                .toList();
    }

    @PostMapping("/whitelist")
    public ResponseEntity<Map<String, Object>> addWhitelist(@RequestBody Map<String, String> body) {
        String type = body.getOrDefault("type", "");
        String value = body.getOrDefault("value", "");
        var key = whitelist.add(type + "," + value);
        if (key == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "白名单条目非法",
                    "type", type,
                    "value", value));
        }
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("type", key.type().name(), "value", key.value()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
