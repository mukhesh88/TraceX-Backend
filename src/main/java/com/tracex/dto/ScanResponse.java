package com.tracex.dto;

import java.time.Instant;

/**
 * REST response payload matching blueprint contract for /api/v1/scan.
 */
public class ScanResponse {

    private String url;
    private String status;
    private float riskScore;
    private double inferenceLatencyMs;
    private FeatureSummaryDto features;
    private Instant timestamp;
    private Boolean fallbackUsed;

    public ScanResponse() {
    }

    public ScanResponse(String url, String status, float riskScore, double inferenceLatencyMs,
                        FeatureSummaryDto features, Instant timestamp) {
        this.url = url;
        this.status = status;
        this.riskScore = riskScore;
        this.inferenceLatencyMs = inferenceLatencyMs;
        this.features = features;
        this.timestamp = timestamp;
    }

    public ScanResponse(String url, String status, float riskScore, double inferenceLatencyMs,
                        FeatureSummaryDto features, Instant timestamp, Boolean fallbackUsed) {
        this(url, status, riskScore, inferenceLatencyMs, features, timestamp);
        this.fallbackUsed = fallbackUsed;
    }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public float getRiskScore() { return riskScore; }
    public void setRiskScore(float riskScore) { this.riskScore = riskScore; }

    public double getInferenceLatencyMs() { return inferenceLatencyMs; }
    public void setInferenceLatencyMs(double inferenceLatencyMs) { this.inferenceLatencyMs = inferenceLatencyMs; }

    public FeatureSummaryDto getFeatures() { return features; }
    public void setFeatures(FeatureSummaryDto features) { this.features = features; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public Boolean getFallbackUsed() { return fallbackUsed; }
    public void setFallbackUsed(Boolean fallbackUsed) { this.fallbackUsed = fallbackUsed; }
}
