package com.tracex.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracex.dto.ScanRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /api/v1/scan - Phishing lure URL should be classified as MALICIOUS")
    void testScanMaliciousUrl() throws Exception {
        ScanRequest request = new ScanRequest("https://secure-login.apple-support-verify.com/auth");

        mockMvc.perform(post("/api/v1/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.url", is("https://secure-login.apple-support-verify.com/auth")))
                .andExpect(jsonPath("$.status", is("MALICIOUS")))
                .andExpect(jsonPath("$.riskScore", greaterThanOrEqualTo(0.60)))
                .andExpect(jsonPath("$.inferenceLatencyMs", notNullValue()))
                .andExpect(jsonPath("$.features.shannonEntropy", greaterThan(2.0)))
                .andExpect(jsonPath("$.features.isPunycode", is(false)))
                .andExpect(jsonPath("$.features.subdomainCount", greaterThanOrEqualTo(1)))
                .andExpect(jsonPath("$.features.flaggedKeywords", hasItems("secure", "login", "verify")))
                .andExpect(jsonPath("$.timestamp", notNullValue()));
    }

    @Test
    @DisplayName("POST /api/v1/scan - Benign URL should be classified as BENIGN")
    void testScanBenignUrl() throws Exception {
        ScanRequest request = new ScanRequest("https://google.com");

        mockMvc.perform(post("/api/v1/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.url", is("https://google.com")))
                .andExpect(jsonPath("$.status", is("BENIGN")))
                .andExpect(jsonPath("$.riskScore", lessThan(0.60)))
                .andExpect(jsonPath("$.features.subdomainCount", is(0)));
    }

    @Test
    @DisplayName("POST /api/v1/scan - Groww login should be classified as BENIGN")
    void testGrowwLoginBenign() throws Exception {
        ScanRequest request = new ScanRequest("https://groww.in/login/enter");

        mockMvc.perform(post("/api/v1/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("BENIGN")))
                .andExpect(jsonPath("$.riskScore", lessThan(0.60)));
    }

    @Test
    @DisplayName("POST /api/v1/scan - Google search with long base64 query should be classified as BENIGN")
    void testGoogleSearchLongQueryBenign() throws Exception {
        ScanRequest request = new ScanRequest("https://www.google.com/search?q=scamadvisor&oq=&gs_lcrp=EgZjaHJvbUqCQgAEEUYOxjCAzIJCAAQRRg7GMIDMgkIARBFGDsYwgMyCQgCEEUYOxjCAzIJCAMQRRg7GMIDMgkIBBBFGEMSWgMyCQgFE");

        mockMvc.perform(post("/api/v1/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("BENIGN")))
                .andExpect(jsonPath("$.riskScore", lessThan(0.60)));
    }

    @Test
    @DisplayName("GET /api/v1/history - Returns paginated scan records")
    void testGetHistory() throws Exception {
        mockMvc.perform(get("/api/v1/history")
                .param("page", "0")
                .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", notNullValue()));
    }

    @Test
    @DisplayName("GET /api/v1/stats - Returns aggregated metrics")
    void testGetStats() throws Exception {
        mockMvc.perform(get("/api/v1/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalScans", greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.maliciousCount", greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.benignCount", greaterThanOrEqualTo(0)));
    }
}
