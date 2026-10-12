package com.tracex.ml;

/**
 * Result of ML/Heuristic inference for URL risk classification.
 */
public class InferenceResult {
    private final float riskScore;
    private final String status; // "MALICIOUS" or "BENIGN"
    private final double inferenceLatencyMs;
    private final boolean fallbackUsed;

    public InferenceResult(float riskScore, String status, double inferenceLatencyMs, boolean fallbackUsed) {
        this.riskScore = Math.max(0.0f, Math.min(1.0f, riskScore));
        this.status = status;
        this.inferenceLatencyMs = inferenceLatencyMs;
        this.fallbackUsed = fallbackUsed;
    }

    public float getRiskScore() {
        return riskScore;
    }

    public String getStatus() {
        return status;
    }

    public double getInferenceLatencyMs() {
        return inferenceLatencyMs;
    }

    public boolean isFallbackUsed() {
        return fallbackUsed;
    }

    @Override
    public String toString() {
        return "InferenceResult{" +
                "riskScore=" + riskScore +
                ", status='" + status + '\'' +
                ", inferenceLatencyMs=" + inferenceLatencyMs +
                ", fallbackUsed=" + fallbackUsed +
                '}';
    }
}
