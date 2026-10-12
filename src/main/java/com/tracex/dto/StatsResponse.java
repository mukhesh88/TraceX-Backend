package com.tracex.dto;

public class StatsResponse {

    private long totalScans;
    private long maliciousCount;
    private long benignCount;
    private double maliciousRatio;
    private double averageLatencyMs;

    public StatsResponse() {
    }

    public StatsResponse(long totalScans, long maliciousCount, long benignCount, double maliciousRatio, double averageLatencyMs) {
        this.totalScans = totalScans;
        this.maliciousCount = maliciousCount;
        this.benignCount = benignCount;
        this.maliciousRatio = maliciousRatio;
        this.averageLatencyMs = averageLatencyMs;
    }

    public long getTotalScans() { return totalScans; }
    public void setTotalScans(long totalScans) { this.totalScans = totalScans; }

    public long getMaliciousCount() { return maliciousCount; }
    public void setMaliciousCount(long maliciousCount) { this.maliciousCount = maliciousCount; }

    public long getBenignCount() { return benignCount; }
    public void setBenignCount(long benignCount) { this.benignCount = benignCount; }

    public double getMaliciousRatio() { return maliciousRatio; }
    public void setMaliciousRatio(double maliciousRatio) { this.maliciousRatio = maliciousRatio; }

    public double getAverageLatencyMs() { return averageLatencyMs; }
    public void setAverageLatencyMs(double averageLatencyMs) { this.averageLatencyMs = averageLatencyMs; }
}
