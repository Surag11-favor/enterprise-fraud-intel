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
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "bid", "pw", "buzz", "click", "rest", "cam"
    );

    // Deceptive keywords often found in fraudulent links
    private static final Set<String> DECEPTIVE_KEYWORDS = Set.of(
        "login", "verify", "secure", "account", "update", "signin", "banking", "support", "billing"
    );

    // Social Media specific detection
    private static final Set<String> SOCIAL_MEDIA_BRANDS = Set.of(
        "facebook", "twitter", "instagram", "tiktok", "linkedin", "snapchat", "youtube", "whatsapp", "telegram", "x", "paypal"
    );

    private static final Set<String> SHORTENER_DOMAINS = Set.of(
        "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "rebrand.ly"
    );

    private static final Set<String> SOCIAL_SCAM_KEYWORDS = Set.of(
        "giveaway", "free followers", "followers", "nft raffle", "crypto gift", "claim", "hack", "disabled"
    );

    public Map<String, Object> analyzeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return buildResponse("LOW", 0.0, "Neutral", "Empty payload provided.");
        }

        String url = rawUrl.trim().toLowerCase();
        double totalScore = 0.0;
        List<String> findings = new ArrayList<>();

        // 0. Shortener Detection (Cloaking Warning)
        for (String shortener : SHORTENER_DOMAINS) {
            if (url.contains(shortener)) {
                totalScore += 25.0;
                findings.add("URL Shortener detected (Cloaking risk)");
                break;
            }
        }

        // 1. Protocol Layer
        if (!url.startsWith("https://")) {
            totalScore += 40.0;
            findings.add("Non-HTTPS protocol (Unsecured)");
        }

        try {
            URL parsedUrl = new URL(url.startsWith("http") ? url : "https://" + url);
            String host = parsedUrl.getHost();
            String path = parsedUrl.getPath();
            
            String[] parts = host.split("\\.");
            String domain = parts.length >= 2 ? parts[parts.length - 2] : host;
            String tld = parts.length >= 1 ? parts[parts.length - 1] : "";

            // 2. High-Trust Brand Recognition
            boolean isProfessionalTrusted = false;
            for (String brand : TRUSTED_BRANDS) {
                if (host.equals(brand + ".com") || host.endsWith("." + brand + ".com")) {
                    isProfessionalTrusted = true;
                    break;
                }
            }
            if (isProfessionalTrusted) return buildResponse("LOW", 5.0, "Positive", "Verified high-trust entity.");

            // 3. Typosquatting
            for (String brand : TRUSTED_BRANDS) {
                if (calculateLevenshteinDistance(domain, brand) == 1) {
                    totalScore += 50.0;
                    findings.add("Potential Typosquatting detected");
                    break;
                }
            }

            // 4. Entropy & TLD Reputation
            if (calculateEntropy(domain) > 3.5) {
                totalScore += 30.0;
                findings.add("High Entropy Domain");
            }
            if (SUSPICIOUS_TLDS.contains(tld)) {
                totalScore += 25.0;
                findings.add("Suspicious TLD (." + tld + ")");
                for (String brand : SOCIAL_MEDIA_BRANDS) {
                    if (domain.contains(brand)) {
                        totalScore += 30.0;
                        findings.add("Social Media Phishing pattern");
                        break;
                    }
                }
            }

            // 5. Deep Content Analysis (The "All Files" Request)
            String pageContent = fetchPageContent(url);
            if (pageContent != null && !pageContent.isEmpty()) {
                // Heuristic: Hidden Iframes (Common in drive-by downloads)
                if (pageContent.contains("<iframe") && (pageContent.contains("visibility:hidden") || pageContent.contains("display:none"))) {
                    totalScore += 40.0;
                    findings.add("Deep Scan: Hidden iframes detected (Drive-by potential)");
                }

                // Heuristic: Malicious script patterns (Simple obfuscation check)
                if (pageContent.contains("eval(unescape(") || pageContent.contains("document.write(unescape(")) {
                    totalScore += 50.0;
                    findings.add("Deep Scan: Malicious script obfuscation detected");
                }

                // Heuristic: Phishing Form Detection
                if (pageContent.contains("<form") && (pageContent.contains("password") || pageContent.contains("creditcard") || pageContent.contains("ssn"))) {
                    totalScore += 35.0;
                    findings.add("Deep Scan: Credential harvesting form detected");
                }

                // Social Scam Content Matching
                long contentScamMatches = SOCIAL_SCAM_KEYWORDS.stream().filter(pageContent::contains).count();
                if (contentScamMatches > 0) {
                    totalScore += (15.0 * contentScamMatches);
                    findings.add("Deep Scan: Social Scam keywords in page content (" + contentScamMatches + ")");
                }
            } else if (totalScore > 10) {
                totalScore += 15.0; // Bonus risk if we can't scrape a suspicious link
                findings.add("Deep Scan: Target content unreachable (Hostile/Ephemeral cloaked link)");
            }

        } catch (Exception e) {
            return buildResponse("HIGH", 95.0, "Highly Suspicious", "Deep Analysis Failure: Targeted payload likely malicious. Flagged as HIGH RISK.");
        }

        // Final Aggregation
        double finalScore = Math.min(totalScore, 100.0);
        String riskLevel = finalScore >= 80.0 ? "BLOCK" : (finalScore >= 40.0 ? "MEDIUM" : "LOW");
        String sentiment = finalScore >= 80.0 ? "Highly Suspicious" : (finalScore >= 40.0 ? "Negative" : "Neutral");
        
        applyMitigationRules(riskLevel.equals("BLOCK") ? "BLOCK" : (riskLevel.equals("MEDIUM") ? "CHALLENGE" : "NONE"), url, String.join(", ", findings));

        return buildResponse(riskLevel, finalScore, sentiment, findings.isEmpty() ? "Verified Safe URL." : "Findings: " + String.join(", ", findings));
    }

    private String fetchPageContent(String urlString) {
        try {
            URL url = new URL(urlString.startsWith("http") ? urlString : "https://" + urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Enterprise-Threat-Intel/1.0");
            
            if (conn.getResponseCode() == 200) {
                Scanner scanner = new Scanner(conn.getInputStream()).useDelimiter("\\A");
                return scanner.hasNext() ? scanner.next().toLowerCase() : "";
            }
        } catch (Exception e) {
            return null; // Return null to indicate scraping failure
        }
        return null;
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

