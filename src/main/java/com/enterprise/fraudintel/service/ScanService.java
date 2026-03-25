package com.enterprise.fraudintel.service;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import org.springframework.stereotype.Service;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class ScanService {

    private final MitigationRuleRepository ruleRepository;
    private final AuditLogRepository auditLogRepository;

    public ScanService(MitigationRuleRepository ruleRepository, AuditLogRepository auditLogRepository) {
        this.ruleRepository = ruleRepository;
        this.auditLogRepository = auditLogRepository;
    }

    // High-Trust Brands to protect against Typosquatting
    private static final Set<String> TRUSTED_BRANDS = Set.of(
        "google", "microsoft", "apple", "amazon", "facebook", "netflix", 
        "paypal", "chase", "bankofamerica", "wellsfargo", "railway", "github"
    );

    // Suspicious TLDs commonly used in phishing
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "bid", "pw", "buzz", "click"
    );

    // Deceptive keywords often found in fraudulent links
    private static final Set<String> DECEPTIVE_KEYWORDS = Set.of(
        "login", "verify", "secure", "account", "update", "signin", "banking", "support", "billing"
    );

    public Map<String, Object> analyzeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return buildResponse("LOW", 0.0, "Neutral", "Empty payload provided.");
        }

        String url = rawUrl.trim().toLowerCase();
        double totalScore = 0.0;
        List<String> findings = new ArrayList<>();

        // 1. Protocol Layer (Basic but critical)
        if (!url.startsWith("https://")) {
            totalScore += 40.0;
            findings.add("Non-HTTPS protocol (Unsecured)");
        }

        try {
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();
            String path = parsedUrl.getPath();
            
            // Extract domain and TLD
            String[] parts = host.split("\\.");
            String domain = parts.length >= 2 ? parts[parts.length - 2] : host;
            String tld = parts.length >= 1 ? parts[parts.length - 1] : "";

            // 2. High-Trust Brand Recognition (Whitelist/Trust Factor)
            boolean isProfessionalTrusted = false;
            for (String brand : TRUSTED_BRANDS) {
                if (host.equals(brand + ".com") || host.endsWith("." + brand + ".com") || host.endsWith("." + brand + ".app")) {
                    isProfessionalTrusted = true;
                    break;
                }
            }

            if (isProfessionalTrusted) {
                return buildResponse("LOW", 5.0, "Positive", "Verified high-trust entity. No threats detected.");
            }

            // 3. Typosquatting Detection (Levenshtein Distance)
            for (String brand : TRUSTED_BRANDS) {
                if (calculateLevenshteinDistance(domain, brand) == 1) {
                    totalScore += 50.0;
                    findings.add("Potential Typosquatting (Deceptive Brand name)");
                    break;
                }
            }

            // 4. Entropy Layer (DGA / Randomness Detection)
            double entropy = calculateEntropy(domain);
            if (entropy > 3.5) { // High randomness is suspicious
                totalScore += 30.0;
                findings.add("High Entropy Domain (Suspicious Randomness)");
            }

            // 5. TLD Reputation Layer
            if (SUSPICIOUS_TLDS.contains(tld)) {
                totalScore += 25.0;
                findings.add("Suspicious TLD reputation (." + tld + ")");
            }

            // 6. Deceptive Pattern Layer (Keywords in Subdomain or Path)
            String fullContext = (host + path).replace(".", " ");
            long keywordMatches = DECEPTIVE_KEYWORDS.stream()
                .filter(fullContext::contains)
                .count();
            
            if (keywordMatches > 0) {
                totalScore += (15.0 * keywordMatches);
                findings.add("Deceptive patterns detected (" + keywordMatches + " keywords)");
            }

            // 7. Structural Integrity (Multi-hyphen detection)
            if (host.chars().filter(ch -> ch == '-').count() > 2) {
                totalScore += 20.0;
                findings.add("Excessive domain hyphenation");
            }

            // 8. Reachability Verification (Professional Liveness check)
            if (totalScore > 20) { // Only check liveness if there are some findings
                if (!isReachable(url)) {
                    totalScore += 10.0;
                    findings.add("Unresponsive/Dead link (Common in ephemeral phishing)");
                }
            }

        } catch (Exception e) {
            return buildResponse("HIGH", 90.0, "Highly Suspicious", "Malformed URL or logic failure. Flagged as HIGH RISK.");
        }

        // Aggregate final Risk Level
        double finalScore = Math.min(totalScore, 100.0);
        String riskLevel = "LOW";
        String sentiment = "Neutral";
        
        if (finalScore >= 80.0) {
            riskLevel = "HIGH";
            sentiment = "Highly Suspicious";
        } else if (finalScore >= 40.0) {
            riskLevel = "MEDIUM";
            sentiment = "Negative";
        } else if (finalScore > 10.0) {
            riskLevel = "LOW";
            sentiment = "Neutral";
        } else {
            riskLevel = "SAFE";
            sentiment = "Positive";
        }

        String summary = findings.isEmpty() ? "Standard URL verified." : "Analysis findings: " + String.join(", ", findings);
        
        // --- NEW: Rule Engine Integration ---
        if (finalScore >= 80.0) {
            applyMitigationRules("BLOCK", url, "High Risk Payload detected");
            riskLevel = "BLOCK"; // Override for "Enterprise" feel
        } else if (finalScore >= 40.0) {
            applyMitigationRules("CHALLENGE", url, "Suspicious activity detected");
        }

        return buildResponse(riskLevel, finalScore, sentiment, summary);
    }

    private void applyMitigationRules(String actionLabel, String url, String reason) {
        List<MitigationRule> activeRules = ruleRepository.findAll().stream()
            .filter(MitigationRule::isEnabled)
            .filter(r -> r.getAction().equalsIgnoreCase(actionLabel))
            .toList();

        if (!activeRules.isEmpty()) {
            AuditLog log = new AuditLog();
            log.setAction(actionLabel);
            log.setPerformedBy("SYSTEM-ENGINE");
            log.setDetails(actionLabel + " applied to " + url + " due to " + reason);
            auditLogRepository.save(log);
        }
    }

    private double calculateEntropy(String s) {
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.put(c, freq.getOrDefault(c, 0) + 1);
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = (double) count / s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private int calculateLevenshteinDistance(String x, String y) {
        int[][] dp = new int[x.length() + 1][y.length() + 1];
        for (int i = 0; i <= x.length(); i++) {
            for (int j = 0; j <= y.length(); j++) {
                if (i == 0) dp[i][j] = j;
                else if (j == 0) dp[i][j] = i;
                else dp[i][j] = Math.min(Math.min(dp[i - 1][j - 1] + (x.charAt(i - 1) == y.charAt(j - 1) ? 0 : 1), dp[i - 1][j] + 1), dp[i][j - 1] + 1);
            }
        }
        return dp[x.length()][y.length()];
    }

    private boolean isReachable(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(2000); 
            connection.setReadTimeout(2000);
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Enterprise-Detection-Module/1.0");
            int responseCode = connection.getResponseCode();
            return responseCode >= 200 && responseCode < 400;
        } catch (Exception e) {
            return false;
        }
    }

    private Map<String, Object> buildResponse(String riskLevel, double riskScore, String sentiment, String summary) {
        Map<String, Object> response = new HashMap<>();
        response.put("riskLevel", riskLevel);
        response.put("riskScore", riskScore);
        response.put("sentiment", sentiment);
        response.put("summary", summary);
        return response;
    }
}

