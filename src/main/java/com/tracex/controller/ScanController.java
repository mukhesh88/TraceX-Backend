package com.tracex.controller;

import com.tracex.dto.*;
import com.tracex.engine.ExtractedFeatures;
import com.tracex.engine.FeatureExtractionEngine;
import com.tracex.entity.ScanRecord;
import com.tracex.ml.InferenceResult;
import com.tracex.ml.OnnxInferenceService;
import com.tracex.repository.ScanRecordRepository;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/api/v1")
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.OPTIONS})
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final FeatureExtractionEngine featureEngine;
    private final OnnxInferenceService inferenceService;
    private final ScanRecordRepository scanRepository;

    public ScanController(FeatureExtractionEngine featureEngine,
                          OnnxInferenceService inferenceService,
                          ScanRecordRepository scanRepository) {
        this.featureEngine = featureEngine;
        this.inferenceService = inferenceService;
        this.scanRepository = scanRepository;
    }

    /**
     * POST /api/v1/scan
     * Extracts lexical features and executes low-latency ML inference.
     */
    @PostMapping("/scan")
    public ResponseEntity<ScanResponse> scanUrl(@Valid @RequestBody ScanRequest request) {
        String url = request.getUrl();
        log.debug("Received scan request for URL: {}", url);

        // 1. Feature Extraction (Zero network I/O)
        ExtractedFeatures features = featureEngine.extract(url);

        // 2. ML / ONNX Inference
        InferenceResult inference = inferenceService.infer(features);

        Instant now = Instant.now();

        // 3. Asynchronously / Synchronously persist to database
        try {
            String keywordsStr = String.join(",", features.getFlaggedKeywords());
            ScanRecord record = new ScanRecord(
                features.getRawUrl(),
                inference.getStatus(),
                inference.getRiskScore(),
                inference.getInferenceLatencyMs(),
                features.getShannonEntropy(),
                features.isPunycode(),
                (int) features.getSubdomainCount(),
                keywordsStr,
                features.hasIpAddress(),
                features.getTldRiskWeight(),
                now
            );
            scanRepository.save(record);
        } catch (Exception e) {
            log.error("Failed to persist scan record: {}", e.getMessage());
        }

        // 4. Assemble response matching blueprint
        FeatureSummaryDto summary = new FeatureSummaryDto(
            features.getShannonEntropy(),
            features.isPunycode(),
            (int) features.getSubdomainCount(),
            features.getFlaggedKeywords()
        );
        summary.setUrlLength(features.getUrlLength());
        summary.setHostnameLength(features.getHostnameLength());
        summary.setPathLength(features.getPathLength());
        summary.setHasIpAddress(features.hasIpAddress());
        summary.setSymbolCountAt((int) features.getSymbolCountAt());
        summary.setSymbolCountHyphen((int) features.getSymbolCountHyphen());
        summary.setTldRiskWeight(features.getTldRiskWeight());
        summary.setDigitToLetterRatio(features.getDigitToLetterRatio());
        summary.setAllFeatures(features.getFeatureMap());

        ScanResponse response = new ScanResponse(
            features.getRawUrl(),
            inference.getStatus(),
            inference.getRiskScore(),
            inference.getInferenceLatencyMs(),
            summary,
            now,
            inference.isFallbackUsed()
        );

        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/v1/history
     * Returns paginated previous scan logs stored in the database.
     */
    @GetMapping("/history")
    public ResponseEntity<Page<ScanRecord>> getHistory(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(Math.max(0, page), Math.min(100, Math.max(1, size)));
        Page<ScanRecord> result = scanRepository.findAllByOrderByTimestampDesc(pageable);
        return ResponseEntity.ok(result);
    }

    /**
     * GET /api/v1/stats
     * Telemetry aggregates for real-time dashboard metrics.
     */
    @GetMapping("/stats")
    public ResponseEntity<StatsResponse> getStats() {
        long total = scanRepository.count();
        long malicious = scanRepository.countByStatus("MALICIOUS");
        long benign = scanRepository.countByStatus("BENIGN");
        Double avgLatency = scanRepository.findAverageLatency();

        double maliciousRatio = total > 0 ? (double) malicious / total : 0.0;
        double roundedLatency = avgLatency != null ? Math.round(avgLatency * 100.0) / 100.0 : 0.0;

        StatsResponse stats = new StatsResponse(
            total,
            malicious,
            benign,
            Math.round(maliciousRatio * 1000.0) / 1000.0,
            roundedLatency
        );

        return ResponseEntity.ok(stats);
    }
}
