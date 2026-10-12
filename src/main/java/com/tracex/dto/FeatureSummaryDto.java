package com.tracex.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

/**
 * Feature diagnostics matching both the blueprint contract and extended telemetry.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FeatureSummaryDto {

    // Blueprint specified fields
    private double shannonEntropy;
    private boolean isPunycode;
    private int subdomainCount;
    private List<String> flaggedKeywords;

    // Extended numeric telemetry fields (helpful for the dashboard radar/breakdown)
    private Float urlLength;
    private Float hostnameLength;
    private Float pathLength;
    private Boolean hasIpAddress;
    private Integer symbolCountAt;
    private Integer symbolCountHyphen;
    private Float tldRiskWeight;
    private Float digitToLetterRatio;
    private Map<String, Object> allFeatures;

    public FeatureSummaryDto() {
    }

    public FeatureSummaryDto(double shannonEntropy, boolean isPunycode, int subdomainCount, List<String> flaggedKeywords) {
        this.shannonEntropy = shannonEntropy;
        this.isPunycode = isPunycode;
        this.subdomainCount = subdomainCount;
        this.flaggedKeywords = flaggedKeywords;
    }

    public double getShannonEntropy() { return shannonEntropy; }
    public void setShannonEntropy(double shannonEntropy) { this.shannonEntropy = shannonEntropy; }

    public boolean getIsPunycode() { return isPunycode; }
    public void setIsPunycode(boolean punycode) { isPunycode = punycode; }

    public int getSubdomainCount() { return subdomainCount; }
    public void setSubdomainCount(int subdomainCount) { this.subdomainCount = subdomainCount; }

    public List<String> getFlaggedKeywords() { return flaggedKeywords; }
    public void setFlaggedKeywords(List<String> flaggedKeywords) { this.flaggedKeywords = flaggedKeywords; }

    public Float getUrlLength() { return urlLength; }
    public void setUrlLength(Float urlLength) { this.urlLength = urlLength; }

    public Float getHostnameLength() { return hostnameLength; }
    public void setHostnameLength(Float hostnameLength) { this.hostnameLength = hostnameLength; }

    public Float getPathLength() { return pathLength; }
    public void setPathLength(Float pathLength) { this.pathLength = pathLength; }

    public Boolean getHasIpAddress() { return hasIpAddress; }
    public void setHasIpAddress(Boolean hasIpAddress) { this.hasIpAddress = hasIpAddress; }

    public Integer getSymbolCountAt() { return symbolCountAt; }
    public void setSymbolCountAt(Integer symbolCountAt) { this.symbolCountAt = symbolCountAt; }

    public Integer getSymbolCountHyphen() { return symbolCountHyphen; }
    public void setSymbolCountHyphen(Integer symbolCountHyphen) { this.symbolCountHyphen = symbolCountHyphen; }

    public Float getTldRiskWeight() { return tldRiskWeight; }
    public void setTldRiskWeight(Float tldRiskWeight) { this.tldRiskWeight = tldRiskWeight; }

    public Float getDigitToLetterRatio() { return digitToLetterRatio; }
    public void setDigitToLetterRatio(Float digitToLetterRatio) { this.digitToLetterRatio = digitToLetterRatio; }

    public Map<String, Object> getAllFeatures() { return allFeatures; }
    public void setAllFeatures(Map<String, Object> allFeatures) { this.allFeatures = allFeatures; }
}
