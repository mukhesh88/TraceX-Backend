package com.tracex.engine;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Encapsulates the extracted lexical and structural features of a URL.
 */
public class ExtractedFeatures {
    private final String rawUrl;
    private final String normalizedUrl;
    private final String scheme;
    private final String hostname;
    private final String path;
    private final String query;

    // 12 distinct numeric features in standardized order for ML tensor input
    private final float urlLength;             // 1
    private final float hostnameLength;        // 2
    private final float pathLength;            // 3
    private final float shannonEntropy;        // 4
    private final float subdomainCount;        // 5
    private final float hasIpAddress;          // 6 (0.0f or 1.0f)
    private final float isPunycode;            // 7 (0.0f or 1.0f)
    private final float symbolCountAt;         // 8
    private final float symbolCountHyphen;     // 9
    private final float suspiciousKeywordFlag; // 10 (0.0f or 1.0f)
    private final float tldRiskWeight;         // 11 (0.0f to 1.0f)
    private final float digitToLetterRatio;    // 12

    // Descriptive metadata for reporting and forensics
    private final List<String> flaggedKeywords;
    private final Map<String, Object> featureMap;

    public ExtractedFeatures(
            String rawUrl,
            String normalizedUrl,
            String scheme,
            String hostname,
            String path,
            String query,
            float urlLength,
            float hostnameLength,
            float pathLength,
            float shannonEntropy,
            float subdomainCount,
            float hasIpAddress,
            float isPunycode,
            float symbolCountAt,
            float symbolCountHyphen,
            float suspiciousKeywordFlag,
            float tldRiskWeight,
            float digitToLetterRatio,
            List<String> flaggedKeywords,
            Map<String, Object> featureMap) {
        this.rawUrl = rawUrl;
        this.normalizedUrl = normalizedUrl;
        this.scheme = scheme;
        this.hostname = hostname;
        this.path = path;
        this.query = query;
        this.urlLength = urlLength;
        this.hostnameLength = hostnameLength;
        this.pathLength = pathLength;
        this.shannonEntropy = shannonEntropy;
        this.subdomainCount = subdomainCount;
        this.hasIpAddress = hasIpAddress;
        this.isPunycode = isPunycode;
        this.symbolCountAt = symbolCountAt;
        this.symbolCountHyphen = symbolCountHyphen;
        this.suspiciousKeywordFlag = suspiciousKeywordFlag;
        this.tldRiskWeight = tldRiskWeight;
        this.digitToLetterRatio = digitToLetterRatio;
        this.flaggedKeywords = flaggedKeywords != null ? Collections.unmodifiableList(flaggedKeywords) : Collections.emptyList();
        this.featureMap = featureMap != null ? Collections.unmodifiableMap(featureMap) : Collections.emptyMap();
    }

    /**
     * Converts the 12 features into a 1D float array for tensor transformation.
     */
    public float[] toFeatureArray() {
        return new float[] {
            urlLength,
            hostnameLength,
            pathLength,
            shannonEntropy,
            subdomainCount,
            hasIpAddress,
            isPunycode,
            symbolCountAt,
            symbolCountHyphen,
            suspiciousKeywordFlag,
            tldRiskWeight,
            digitToLetterRatio
        };
    }

    public String getRawUrl() { return rawUrl; }
    public String getNormalizedUrl() { return normalizedUrl; }
    public String getScheme() { return scheme; }
    public String getHostname() { return hostname; }
    public String getPath() { return path; }
    public String getQuery() { return query; }

    public float getUrlLength() { return urlLength; }
    public float getHostnameLength() { return hostnameLength; }
    public float getPathLength() { return pathLength; }
    public float getShannonEntropy() { return shannonEntropy; }
    public float getSubdomainCount() { return subdomainCount; }
    public boolean hasIpAddress() { return hasIpAddress > 0.5f; }
    public float getHasIpAddressValue() { return hasIpAddress; }
    public boolean isPunycode() { return isPunycode > 0.5f; }
    public float getIsPunycodeValue() { return isPunycode; }
    public float getSymbolCountAt() { return symbolCountAt; }
    public float getSymbolCountHyphen() { return symbolCountHyphen; }
    public boolean hasSuspiciousKeywords() { return suspiciousKeywordFlag > 0.5f; }
    public float getSuspiciousKeywordFlag() { return suspiciousKeywordFlag; }
    public float getTldRiskWeight() { return tldRiskWeight; }
    public float getDigitToLetterRatio() { return digitToLetterRatio; }

    public List<String> getFlaggedKeywords() { return flaggedKeywords; }
    public Map<String, Object> getFeatureMap() { return featureMap; }
}
