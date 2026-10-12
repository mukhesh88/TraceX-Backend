package com.tracex.engine;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * High-performance, zero-network lexical feature extraction engine.
 * Inspects incoming URLs strictly using static structural, statistical, and lexical indicators.
 */
@Component
public class FeatureExtractionEngine {

    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"
    );

    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^(\\[?[0-9a-fA-F:]+\\]?)$"
    );

    // Common two-part public suffixes
    private static final Set<String> MULTI_PART_SUFFIXES = Set.of(
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "net.nz", "org.nz",
        "com.br", "org.br", "net.br",
        "co.jp", "ne.jp", "or.jp",
        "co.in", "net.in", "org.in", "gov.in",
        "com.cn", "net.cn", "org.cn",
        "com.sg", "com.mx", "com.ar"
    );

    // High abuse TLD risk scoring table
    private static final Map<String, Float> TLD_RISK_MAP = new HashMap<>();
    static {
        // High risk (1.0)
        TLD_RISK_MAP.put("tk", 1.0f);
        TLD_RISK_MAP.put("ml", 1.0f);
        TLD_RISK_MAP.put("ga", 1.0f);
        TLD_RISK_MAP.put("cf", 1.0f);
        TLD_RISK_MAP.put("gq", 1.0f);

        // High risk (0.85)
        TLD_RISK_MAP.put("xyz", 0.85f);
        TLD_RISK_MAP.put("top", 0.85f);
        TLD_RISK_MAP.put("buzz", 0.85f);
        TLD_RISK_MAP.put("work", 0.80f);
        TLD_RISK_MAP.put("icu", 0.80f);
        TLD_RISK_MAP.put("fit", 0.80f);
        TLD_RISK_MAP.put("loan", 0.80f);
        TLD_RISK_MAP.put("surf", 0.75f);
        TLD_RISK_MAP.put("stream", 0.75f);
        TLD_RISK_MAP.put("gdn", 0.75f);
        TLD_RISK_MAP.put("racing", 0.75f);
        TLD_RISK_MAP.put("click", 0.70f);
        TLD_RISK_MAP.put("link", 0.65f);
        TLD_RISK_MAP.put("site", 0.60f);
        TLD_RISK_MAP.put("club", 0.55f);
        TLD_RISK_MAP.put("online", 0.50f);
        TLD_RISK_MAP.put("live", 0.50f);

        // Reputable/standard TLDs
        TLD_RISK_MAP.put("gov", 0.01f);
        TLD_RISK_MAP.put("mil", 0.01f);
        TLD_RISK_MAP.put("edu", 0.02f);
        TLD_RISK_MAP.put("org", 0.04f);
        TLD_RISK_MAP.put("com", 0.05f);
        TLD_RISK_MAP.put("net", 0.05f);
        TLD_RISK_MAP.put("in", 0.03f);  // National ccTLD for India
        TLD_RISK_MAP.put("uk", 0.03f);
        TLD_RISK_MAP.put("de", 0.03f);
        TLD_RISK_MAP.put("fr", 0.03f);
        TLD_RISK_MAP.put("jp", 0.03f);
        TLD_RISK_MAP.put("ca", 0.03f);
        TLD_RISK_MAP.put("au", 0.03f);
        TLD_RISK_MAP.put("us", 0.03f);
        TLD_RISK_MAP.put("io", 0.05f);
        TLD_RISK_MAP.put("dev", 0.05f);
    }

    // Known reputable apex domains to prevent false positives on legitimate services
    private static final Set<String> TRUSTED_APEX_DOMAINS = Set.of(
        "google.com", "google.co.in", "google.co.uk", "google.ca", "google.de",
        "groww.in", "zerodha.com", "upstox.com",
        "apple.com", "microsoft.com", "amazon.com", "amazon.in",
        "github.com", "gitlab.com", "bitbucket.org",
        "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
        "wikipedia.org", "netflix.com", "spotify.com", "reddit.com",
        "bing.com", "duckduckgo.com", "yahoo.com"
    );

    // Security, credential, and urgency tokens frequently leveraged in phishing lures
    private static final List<String> SUSPICIOUS_KEYWORDS = List.of(
        "login", "verify", "banking", "secure", "update", "wallet",
        "account", "signin", "auth", "confirm", "recover", "password",
        "credential", "webscr", "ebayisapi", "security", "validation",
        "payment", "billing", "support", "authenticate"
    );

    /**
     * Extracts all 12 numeric features plus metadata from the given URL string.
     */
    public ExtractedFeatures extract(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("URL must not be null or empty");
        }

        String cleanedUrl = rawUrl.trim();
        String normalizedUrl = cleanedUrl;
        if (!cleanedUrl.contains("://")) {
            normalizedUrl = "https://" + cleanedUrl;
        }

        String scheme = "";
        String hostname = "";
        String path = "";
        String query = "";

        try {
            URI uri = URI.create(normalizedUrl);
            scheme = uri.getScheme() != null ? uri.getScheme() : "https";
            hostname = uri.getHost() != null ? uri.getHost().toLowerCase(Locale.ROOT) : "";
            path = uri.getRawPath() != null ? uri.getRawPath() : "";
            query = uri.getRawQuery() != null ? uri.getRawQuery() : "";
        } catch (Exception e) {
            // Fallback manual parsing for non-standard or malformed URLs
            int schemeEnd = normalizedUrl.indexOf("://");
            if (schemeEnd != -1) {
                scheme = normalizedUrl.substring(0, schemeEnd);
                String rest = normalizedUrl.substring(schemeEnd + 3);
                int slashIdx = rest.indexOf('/');
                int queryIdx = rest.indexOf('?');

                if (slashIdx != -1) {
                    hostname = rest.substring(0, slashIdx).toLowerCase(Locale.ROOT);
                    if (queryIdx != -1 && queryIdx > slashIdx) {
                        path = rest.substring(slashIdx, queryIdx);
                        query = rest.substring(queryIdx + 1);
                    } else {
                        path = rest.substring(slashIdx);
                    }
                } else if (queryIdx != -1) {
                    hostname = rest.substring(0, queryIdx).toLowerCase(Locale.ROOT);
                    query = rest.substring(queryIdx + 1);
                } else {
                    hostname = rest.toLowerCase(Locale.ROOT);
                }
            } else {
                hostname = cleanedUrl.toLowerCase(Locale.ROOT);
            }
        }

        // Strip port if present in hostname
        if (hostname.contains(":")) {
            int colonIdx = hostname.indexOf(':');
            hostname = hostname.substring(0, colonIdx);
        }

        // 1. url_length: Total character count
        float urlLength = cleanedUrl.length();

        // 2. hostname_length: Character count of parsed host
        float hostnameLength = hostname.length();

        // 3. path_length: Length of URI path segment
        float pathLength = path.length();

        // 4. shannon_entropy: Shannon character entropy of the entire URL string
        float shannonEntropy = (float) calculateShannonEntropy(cleanedUrl);

        // 5. subdomain_count: Number of dot-separated labels minus registered domain
        float subdomainCount = calculateSubdomainCount(hostname);

        // 6. has_ip_address: Binary flag (1 if hostname is IPv4 or IPv6)
        float hasIpAddress = isIpAddress(hostname) ? 1.0f : 0.0f;

        // 7. is_punycode: Binary flag (1 if hostname contains "xn--")
        float isPunycode = (hostname.contains("xn--") || cleanedUrl.toLowerCase(Locale.ROOT).contains("xn--")) ? 1.0f : 0.0f;

        // 8. symbol_count_at: Count of '@' symbols in the URL
        float symbolCountAt = countChar(cleanedUrl, '@');

        // 9. symbol_count_hyphen: Count of '-' symbols in the hostname
        float symbolCountHyphen = countChar(hostname, '-');

        // 10. suspicious_keyword_flag & flagged keywords (excludes query params like search terms)
        List<String> flaggedKeywords = findFlaggedKeywords(hostname, path);
        float suspiciousKeywordFlag = flaggedKeywords.isEmpty() ? 0.0f : 1.0f;

        // 11. tld_risk_weight: Risk score assigned to high-abuse TLDs (minimum 0.01 for trusted apex domains)
        float tldRiskWeight = calculateTldRiskWeight(hostname);

        // 12. digit_to_letter_ratio: Ratio of numeric digits to alphabetical characters across the URL
        float digitToLetterRatio = calculateDigitToLetterRatio(cleanedUrl);

        // Structured feature map for detailed diagnostics
        Map<String, Object> featureMap = new LinkedHashMap<>();
        featureMap.put("url_length", urlLength);
        featureMap.put("hostname_length", hostnameLength);
        featureMap.put("path_length", pathLength);
        featureMap.put("shannon_entropy", shannonEntropy);
        featureMap.put("subdomain_count", (int) subdomainCount);
        featureMap.put("has_ip_address", hasIpAddress > 0.5f);
        featureMap.put("is_punycode", isPunycode > 0.5f);
        featureMap.put("symbol_count_at", (int) symbolCountAt);
        featureMap.put("symbol_count_hyphen", (int) symbolCountHyphen);
        featureMap.put("suspicious_keyword_flag", suspiciousKeywordFlag > 0.5f);
        featureMap.put("tld_risk_weight", tldRiskWeight);
        featureMap.put("digit_to_letter_ratio", digitToLetterRatio);

        return new ExtractedFeatures(
            cleanedUrl,
            normalizedUrl,
            scheme,
            hostname,
            path,
            query,
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
            digitToLetterRatio,
            flaggedKeywords,
            featureMap
        );
    }

    /**
     * Calculates Shannon entropy: H(X) = -sum( P(x_i) * log2(P(x_i)) )
     */
    public double calculateShannonEntropy(String input) {
        if (input == null || input.isEmpty()) {
            return 0.0;
        }

        int length = input.length();
        Map<Character, Integer> freqMap = new HashMap<>(length);
        for (int i = 0; i < length; i++) {
            char c = input.charAt(i);
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        double log2 = Math.log(2);
        for (int count : freqMap.values()) {
            double p = (double) count / length;
            entropy -= p * (Math.log(p) / log2);
        }

        return Math.round(entropy * 1000.0) / 1000.0;
    }

    /**
     * Counts subdomains by splitting hostname and accounting for registered domain.
     */
    public int calculateSubdomainCount(String hostname) {
        if (hostname == null || hostname.isEmpty() || isIpAddress(hostname)) {
            return 0;
        }

        // Clean trailing dot
        if (hostname.endsWith(".")) {
            hostname = hostname.substring(0, hostname.length() - 1);
        }

        String[] parts = hostname.split("\\.");
        if (parts.length <= 2) {
            return 0;
        }

        // Check for multi-part suffix like .co.uk
        String potentialSuffix = parts[parts.length - 2] + "." + parts[parts.length - 1];
        if (MULTI_PART_SUFFIXES.contains(potentialSuffix.toLowerCase(Locale.ROOT))) {
            // example.co.uk has 3 parts, subdomains start at index 4
            return Math.max(0, parts.length - 3);
        }

        // standard domain: subdomain.domain.com -> 3 parts - 2 = 1 subdomain
        return Math.max(0, parts.length - 2);
    }

    /**
     * Checks whether the hostname is an IPv4 or IPv6 address.
     */
    public boolean isIpAddress(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return false;
        }

        // IPv4 check
        if (IPV4_PATTERN.matcher(hostname).matches()) {
            String[] octets = hostname.split("\\.");
            if (octets.length == 4) {
                try {
                    for (String octet : octets) {
                        int val = Integer.parseInt(octet);
                        if (val < 0 || val > 255) {
                            return false;
                        }
                    }
                    return true;
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        }

        // IPv6 check (contains at least 2 colons)
        if (hostname.startsWith("[") && hostname.endsWith("]")) {
            return true;
        }
        if (hostname.contains(":") && countChar(hostname, ':') >= 2) {
            return IPV6_PATTERN.matcher(hostname).matches();
        }

        return false;
    }

    public String extractRegisteredDomain(String hostname) {
        if (hostname == null || hostname.isEmpty() || isIpAddress(hostname)) {
            return hostname != null ? hostname : "";
        }
        if (hostname.endsWith(".")) {
            hostname = hostname.substring(0, hostname.length() - 1);
        }
        String[] parts = hostname.split("\\.");
        if (parts.length <= 2) {
            return hostname.toLowerCase(Locale.ROOT);
        }
        String potentialSuffix = parts[parts.length - 2] + "." + parts[parts.length - 1];
        if (MULTI_PART_SUFFIXES.contains(potentialSuffix.toLowerCase(Locale.ROOT))) {
            if (parts.length >= 3) {
                return (parts[parts.length - 3] + "." + potentialSuffix).toLowerCase(Locale.ROOT);
            }
            return hostname.toLowerCase(Locale.ROOT);
        }
        return (parts[parts.length - 2] + "." + parts[parts.length - 1]).toLowerCase(Locale.ROOT);
    }

    public boolean isTrustedApexDomain(String hostname) {
        if (hostname == null || hostname.isEmpty()) return false;
        String registered = extractRegisteredDomain(hostname);
        return TRUSTED_APEX_DOMAINS.contains(registered);
    }

    /**
     * Finds sensitive phishing/credential keywords present in hostname and non-standard path segments.
     * Query string parameters (e.g. search terms) are explicitly excluded to prevent false positives.
     */
    public List<String> findFlaggedKeywords(String hostname, String path) {
        String hostLower = hostname != null ? hostname.toLowerCase(Locale.ROOT) : "";
        String pathLower = path != null ? path.toLowerCase(Locale.ROOT) : "";
        boolean trustedApex = isTrustedApexDomain(hostLower);

        List<String> matched = new ArrayList<>();

        // 1. Check hostname: brand spoofing or credential tokens in host (e.g. secure-login, apple-verify)
        if (!trustedApex) {
            for (String keyword : SUSPICIOUS_KEYWORDS) {
                if (hostLower.contains(keyword)) {
                    matched.add(keyword);
                }
            }
        }

        // 2. Check path segments: flag non-standard path segments (e.g. deep nesting, script files, untrusted hosts)
        // Standard first-level paths on trusted domains (e.g. /login on groww.in or google.com) are legitimate.
        if (!trustedApex) {
            for (String keyword : SUSPICIOUS_KEYWORDS) {
                if (pathLower.contains(keyword) && !matched.contains(keyword)) {
                    matched.add(keyword);
                }
            }
        }

        return matched;
    }

    /**
     * Assigns a risk weight score in [0.0, 1.0] to the hostname's TLD.
     */
    public float calculateTldRiskWeight(String hostname) {
        if (hostname == null || hostname.isEmpty() || isIpAddress(hostname)) {
            return 0.1f;
        }
        if (isTrustedApexDomain(hostname)) {
            return 0.01f;
        }

        int lastDot = hostname.lastIndexOf('.');
        if (lastDot == -1 || lastDot == hostname.length() - 1) {
            return 0.2f;
        }

        String tld = hostname.substring(lastDot + 1).toLowerCase(Locale.ROOT);
        return TLD_RISK_MAP.getOrDefault(tld, 0.05f);
    }

    /**
     * Calculates the ratio of numeric digits to alphabetical letters across the URL.
     */
    public float calculateDigitToLetterRatio(String url) {
        if (url == null || url.isEmpty()) {
            return 0.0f;
        }

        int digits = 0;
        int letters = 0;
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (Character.isDigit(c)) {
                digits++;
            } else if (Character.isLetter(c)) {
                letters++;
            }
        }

        if (letters == 0) {
            return digits > 0 ? (float) digits : 0.0f;
        }

        return (float) Math.round(((float) digits / letters) * 1000.0f) / 1000.0f;
    }

    private int countChar(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) {
                count++;
            }
        }
        return count;
    }
}
