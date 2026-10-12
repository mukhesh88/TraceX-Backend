package com.tracex.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * JPA entity representing persisted scan telemetry and forensics logs.
 */
@Entity
@Table(name = "scan_records", indexes = {
    @Index(name = "idx_scan_timestamp", columnList = "timestamp DESC"),
    @Index(name = "idx_scan_status", columnList = "status")
})
public class ScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "url", length = 2048, nullable = false)
    private String url;

    @Column(name = "status", length = 32, nullable = false)
    private String status;

    @Column(name = "risk_score", nullable = false)
    private float riskScore;

    @Column(name = "inference_latency_ms", nullable = false)
    private double inferenceLatencyMs;

    @Column(name = "shannon_entropy")
    private double shannonEntropy;

    @Column(name = "is_punycode")
    private boolean isPunycode;

    @Column(name = "subdomain_count")
    private int subdomainCount;

    @Column(name = "flagged_keywords", length = 1024)
    private String flaggedKeywords;

    @Column(name = "has_ip_address")
    private boolean hasIpAddress;

    @Column(name = "tld_risk_weight")
    private float tldRiskWeight;

    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;

    public ScanRecord() {
    }

    public ScanRecord(String url, String status, float riskScore, double inferenceLatencyMs,
                      double shannonEntropy, boolean isPunycode, int subdomainCount,
                      String flaggedKeywords, boolean hasIpAddress, float tldRiskWeight,
                      Instant timestamp) {
        this.url = url;
        this.status = status;
        this.riskScore = riskScore;
        this.inferenceLatencyMs = inferenceLatencyMs;
        this.shannonEntropy = shannonEntropy;
        this.isPunycode = isPunycode;
        this.subdomainCount = subdomainCount;
        this.flaggedKeywords = flaggedKeywords;
        this.hasIpAddress = hasIpAddress;
        this.tldRiskWeight = tldRiskWeight;
        this.timestamp = timestamp;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public float getRiskScore() { return riskScore; }
    public void setRiskScore(float riskScore) { this.riskScore = riskScore; }

    public double getInferenceLatencyMs() { return inferenceLatencyMs; }
    public void setInferenceLatencyMs(double inferenceLatencyMs) { this.inferenceLatencyMs = inferenceLatencyMs; }

    public double getShannonEntropy() { return shannonEntropy; }
    public void setShannonEntropy(double shannonEntropy) { this.shannonEntropy = shannonEntropy; }

    public boolean isPunycode() { return isPunycode; }
    public void setPunycode(boolean punycode) { isPunycode = punycode; }

    public int getSubdomainCount() { return subdomainCount; }
    public void setSubdomainCount(int subdomainCount) { this.subdomainCount = subdomainCount; }

    public String getFlaggedKeywords() { return flaggedKeywords; }
    public void setFlaggedKeywords(String flaggedKeywords) { this.flaggedKeywords = flaggedKeywords; }

    public boolean isHasIpAddress() { return hasIpAddress; }
    public void setHasIpAddress(boolean hasIpAddress) { this.hasIpAddress = hasIpAddress; }

    public float getTldRiskWeight() { return tldRiskWeight; }
    public void setTldRiskWeight(float tldRiskWeight) { this.tldRiskWeight = tldRiskWeight; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
}
