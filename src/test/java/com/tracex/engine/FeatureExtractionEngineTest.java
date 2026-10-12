package com.tracex.engine;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FeatureExtractionEngineTest {

    private FeatureExtractionEngine engine;

    @BeforeEach
    void setUp() {
        engine = new FeatureExtractionEngine();
    }

    @Test
    @DisplayName("Should correctly extract all 12 features for a phishing lure URL")
    void testPhishingUrlExtraction() {
        String url = "https://secure-login.apple-support-verify.com/auth";
        ExtractedFeatures features = engine.extract(url);

        assertNotNull(features);
        assertEquals(url.length(), (int) features.getUrlLength());
        assertEquals("secure-login.apple-support-verify.com", features.getHostname());
        assertEquals("/auth", features.getPath());
        assertTrue(features.getShannonEntropy() > 3.0f);
        assertTrue(features.getSubdomainCount() >= 1);
        assertFalse(features.hasIpAddress());
        assertFalse(features.isPunycode());
        assertEquals(0, (int) features.getSymbolCountAt());
        assertTrue(features.getSymbolCountHyphen() >= 3); // secure-login, apple-support-verify
        assertTrue(features.hasSuspiciousKeywords());
        List<String> keywords = features.getFlaggedKeywords();
        assertTrue(keywords.contains("secure"));
        assertTrue(keywords.contains("login"));
        assertTrue(keywords.contains("verify"));

        float[] array = features.toFeatureArray();
        assertEquals(12, array.length);
    }

    @Test
    @DisplayName("Should detect punycode homograph attack in domain")
    void testPunycodeDetection() {
        String url = "https://xn--pple-43d.com/login";
        ExtractedFeatures features = engine.extract(url);

        assertTrue(features.isPunycode());
        assertEquals(1.0f, features.getIsPunycodeValue());
        assertTrue(features.hasSuspiciousKeywords());
        assertTrue(features.getFlaggedKeywords().contains("login"));
    }

    @Test
    @DisplayName("Should detect raw IPv4 address in hostname")
    void testRawIpAddressDetection() {
        String url = "http://192.168.1.100/paypal/login.php";
        ExtractedFeatures features = engine.extract(url);

        assertTrue(features.hasIpAddress());
        assertEquals(1.0f, features.getHasIpAddressValue());
        assertEquals(0, (int) features.getSubdomainCount());
    }

    @Test
    @DisplayName("Should calculate accurate Shannon entropy")
    void testShannonEntropy() {
        // String with identical characters has zero entropy
        double zeroEntropy = engine.calculateShannonEntropy("aaaaaa");
        assertEquals(0.0, zeroEntropy, 0.001);

        // String with mixed characters has higher entropy
        double mixedEntropy = engine.calculateShannonEntropy("abcdef123456");
        assertTrue(mixedEntropy > 3.0);
    }

    @Test
    @DisplayName("Should calculate correct subdomain count for multi-part TLD")
    void testSubdomainCountWithMultiPartTld() {
        // secure.ebanking.co.uk: registered domain is ebanking.co.uk (3 parts), subdomain is secure (1)
        int count = engine.calculateSubdomainCount("secure.ebanking.co.uk");
        assertEquals(1, count);

        // mail.google.com: registered domain is google.com (2 parts), subdomain is mail (1)
        int stdCount = engine.calculateSubdomainCount("mail.google.com");
        assertEquals(1, stdCount);

        // google.com: 0 subdomains
        int zeroCount = engine.calculateSubdomainCount("google.com");
        assertEquals(0, zeroCount);
    }

    @Test
    @DisplayName("Should assign elevated risk weight to high abuse TLDs")
    void testTldRiskWeights() {
        float tkRisk = engine.calculateTldRiskWeight("phishing-target.tk");
        assertEquals(1.0f, tkRisk, 0.001);

        float xyzRisk = engine.calculateTldRiskWeight("account-update.xyz");
        assertEquals(0.85f, xyzRisk, 0.001);

        float comRisk = engine.calculateTldRiskWeight("somedomain.com");
        assertEquals(0.05f, comRisk, 0.001);

        float trustedRisk = engine.calculateTldRiskWeight("google.com");
        assertEquals(0.01f, trustedRisk, 0.001);
    }

    @Test
    @DisplayName("Should compute accurate digit to letter ratio")
    void testDigitToLetterRatio() {
        // 4 digits, 4 letters -> 1.0
        float ratio = engine.calculateDigitToLetterRatio("abcd1234");
        assertEquals(1.0f, ratio, 0.01);
    }

    @Test
    @DisplayName("Google Search query should not flag keywords from query params and have minimal TLD risk")
    void testGoogleSearchDoesNotFlagKeywords() {
        String url = "https://www.google.com/search?q=scamadvisor&oq=&gs_lcrp=EgZjaHJvbUqCQgAEEUYOxjCAzIJ";
        ExtractedFeatures features = engine.extract(url);

        assertTrue(features.getFlaggedKeywords().isEmpty());
        assertFalse(features.hasSuspiciousKeywords());
        assertEquals(0.01f, features.getTldRiskWeight(), 0.001);
        assertTrue(engine.isTrustedApexDomain("www.google.com"));
    }

    @Test
    @DisplayName("Groww login should be recognized as trusted apex domain without false alerts")
    void testGrowwLoginLegitimate() {
        String url = "https://groww.in/login/enter";
        ExtractedFeatures features = engine.extract(url);

        assertTrue(features.getFlaggedKeywords().isEmpty());
        assertFalse(features.hasSuspiciousKeywords());
        assertEquals(0.01f, features.getTldRiskWeight(), 0.001);
        assertTrue(engine.isTrustedApexDomain("groww.in"));
    }
}
