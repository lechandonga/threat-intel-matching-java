package com.github.lechandonga.threatintelmatchingjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 业务5：REST 接口端到端验证。
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "intel.sample.load-on-startup=false",
        "intel.whitelist.file=target/test-whitelist/does-not-exist.txt"
})
class IntelApiWebTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void importThenQueryReturnsTraceableVerdict() throws Exception {
        String stix = """
                {"x_source":"web-stix","objects":[
                  {"type":"indicator","pattern":"[domain-name:value = 'api.malicious.test']",
                   "confidence":92,"labels":["malicious","c2"],
                   "created":"2026-10-05T00:00:00Z","modified":"2026-10-05T00:00:00Z"}]}
                """;
        mockMvc.perform(post("/api/intel/import/stix")
                        .contentType(MediaType.APPLICATION_JSON).content(stix))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(1))
                .andExpect(jsonPath("$.rejected").isArray())
                .andExpect(jsonPath("$.rejected.length()").value(0));

        mockMvc.perform(get("/api/intel/query/domain/api.malicious.test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.found").value(true))
                .andExpect(jsonPath("$.verdict").value("MALICIOUS"))
                .andExpect(jsonPath("$.decidingSource").value("web-stix"))
                .andExpect(jsonPath("$.sources[0].rawConfidence").value(92))
                .andExpect(jsonPath("$.sources[0].deciding").value(true))
                .andExpect(jsonPath("$.decidingRule")
                        .value("MAX_DECAYED_CONFIDENCE_THEN_WEIGHT_THEN_SOURCE_NAME"));
    }

    @Test
    void badRowsComeBackWithDistinguishableReasons() throws Exception {
        String doc = """
                {"source":"web-flat","records":[
                  {"indicator_type":"ip","value":"300.1.1.1","disposition":"malicious",
                   "confidence":80,"observed_at":"2026-10-05T00:00:00Z"},
                  {"indicator_type":"ip","value":"203.0.113.9","disposition":"nope",
                   "confidence":80,"observed_at":"2026-10-05T00:00:00Z"},
                  {"indicator_type":"ip","value":"203.0.113.8","disposition":"malicious",
                   "confidence":101,"observed_at":"2026-10-05T00:00:00Z"}]}
                """;
        mockMvc.perform(post("/api/intel/import/flat")
                        .contentType(MediaType.APPLICATION_JSON).content(doc))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(0))
                .andExpect(jsonPath("$.rejected.length()").value(3))
                .andExpect(jsonPath("$.rejected[0].reason").value("MALFORMED_IP"))
                .andExpect(jsonPath("$.rejected[1].reason").value("UNSUPPORTED_DISPOSITION"))
                .andExpect(jsonPath("$.rejected[2].reason").value("CONFIDENCE_OUT_OF_RANGE"));
    }

    @Test
    void whitelistAdditionOverridesMaliciousVerdict() throws Exception {
        String doc = """
                {"source":"wl-src","records":[
                  {"indicator_type":"ip","value":"192.0.2.55","disposition":"malicious",
                   "confidence":100,"observed_at":"2026-10-05T00:00:00Z"}]}
                """;
        mockMvc.perform(post("/api/intel/import/flat")
                        .contentType(MediaType.APPLICATION_JSON).content(doc))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/intel/whitelist")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"ip\",\"value\":\"192.0.2.55\"}"))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/intel/query/ip/192.0.2.55"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict").value("HARMLESS"))
                .andExpect(jsonPath("$.whitelisted").value(true))
                .andExpect(jsonPath("$.sources.length()").value(1));
    }

    @Test
    void unknownIndicatorIsHarmlessWithNoIntelRule() throws Exception {
        mockMvc.perform(get("/api/intel/query/ip/203.0.113.250"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.found").value(false))
                .andExpect(jsonPath("$.verdict").value("HARMLESS"))
                .andExpect(jsonPath("$.decidingRule").value("NO_INTEL"));
    }

    @Test
    void illegalQueryValueReturns400() throws Exception {
        mockMvc.perform(get("/api/intel/query/ip/not-an-ip"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }
}
