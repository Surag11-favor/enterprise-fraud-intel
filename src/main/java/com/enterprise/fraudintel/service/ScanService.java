package com.enterprise.fraudintel.service;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import org.springframework.stereotype.Service;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.*;

@Service
public class ScanService {

    private final MitigationRuleRepository ruleRepository;
    private final AuditLogRepository auditLogRepository;

    public ScanService(MitigationRuleRepository ruleRepository, AuditLogRepository auditLogRepository) {
        this.ruleRepository = ruleRepository;
        this.auditLogRepository = auditLogRepository;
    }

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
                totalScore += 15.0;
                findings.add("URL Shortener detected (Cloaking context)");
                break;
            }
        }

        // 0.1 Deceptive Keyword Heuristics
        for (String keyword : DECEPTIVE_KEYWORDS) {
            if (url.contains(keyword)) {
                totalScore += 10.0;
                findings.add("Deceptive keyword identified: " + keyword);
            }
        }

        // 1. Protocol Layer
        if (!url.startsWith("https://")) {
            totalScore += 30.0; // Reduced penalty
            findings.add("Non-HTTPS protocol (Unsecured transit)");
        }

        try {
            URL parsedUrl = URI.create(url.startsWith("http") ? url : "https://" + url).toURL();
            String host = parsedUrl.getHost();
            
            String[] parts = host.split("\\.");
            String domain = parts.length >= 2 ? parts[parts.length - 2] : host;
            String tld = parts.length >= 1 ? parts[parts.length - 1] : "";

            // 2. Entropy & TLD Reputation
            if (calculateEntropy(domain) > 4.2) { // Increased threshold to avoid normal random names
                totalScore += 20.0;
                findings.add("High Entropy Domain Name");
            }
            if (SUSPICIOUS_TLDS.contains(tld)) {
                totalScore += 25.0;
                findings.add("Suspicious TLD (." + tld + ")");
                for (String brand : SOCIAL_MEDIA_BRANDS) {
                    if (domain.contains(brand)) {
                        totalScore += 30.0;
                        findings.add("Social Media Phishing pattern in Domain");
                        break;
                    }
                }
            }

            // 3. Deep Content Analysis (The "All Files" Request)
            String pageContent = fetchPageContent(url);
            if (pageContent != null && !pageContent.isEmpty()) {
                
                // Heuristic: Malicious script patterns or heavy obfuscation
                if (pageContent.contains("eval(unescape(") || pageContent.contains("document.write(unescape(")) {
                    totalScore += 45.0;
                    findings.add("Deep Scan: Malicious script obfuscation detected");
                }
                
                // Heuristic: Suspicious External Iframes/Scripts
                boolean hasSuspiciousExternalSource = false;
                for (String susTld : SUSPICIOUS_TLDS) {
                    if (pageContent.matches(".*<(iframe|script)[^>]+src=[\"'].*\\." + susTld + "[\"'].*")) {
                        hasSuspiciousExternalSource = true;
                        break;
                    }
                }
                if (hasSuspiciousExternalSource) {
                    totalScore += 40.0;
                    findings.add("Deep Scan: Suspicious external payload integration");
                }

                // Heuristic: Phishing Form Detection (Only flag if posting externally)
                if (pageContent.contains("<form") && (pageContent.contains("password") || pageContent.contains("creditcard") || pageContent.contains("ssn"))) {
                    // Simple check if form action contains a different absolute URL
                    if (pageContent.matches(".*<form[^>]+action=[\"']https?://.*") && !pageContent.contains("action=\"" + (url.startsWith("https") ? "https" : "http") + "://" + host)) {
                        totalScore += 40.0;
                        findings.add("Deep Scan: External Credential Harvesting form detected");
                    }
                }

                // Social Scam Content Matching
                long contentScamMatches = SOCIAL_SCAM_KEYWORDS.stream().filter(pageContent::contains).count();
                if (contentScamMatches > 3) { // Require high density (e.g. at least 4 keywords)
                    totalScore += (10.0 * contentScamMatches);
                    findings.add("Deep Scan: High density of Social Scam keywords (" + contentScamMatches + ")");
                } else if (contentScamMatches > 0 && SUSPICIOUS_TLDS.contains(tld)) {
                    // Or if it's already a shady domain, be stricter
                    totalScore += (15.0 * contentScamMatches);
                    findings.add("Deep Scan: Social Scam keywords on suspicious domain (" + contentScamMatches + ")");
                }

            } else if (totalScore > 20) {
                totalScore += 15.0; 
                findings.add("Deep Scan: Target content unreachable on a suspicious link (Evasion)");
            }

        } catch (Exception e) {
            return buildResponse("HIGH", 95.0, "Highly Suspicious", "Deep Analysis Failure: Targeted payload severely malformed or hostile.");
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
            // Ensure URL starts with http/https for URI.create to work reliably
            String normalizedUrlString = urlString.startsWith("http") ? urlString : "https://" + urlString;
            HttpURLConnection conn = (HttpURLConnection) URI.create(normalizedUrlString).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Enterprise-Threat-Intel/1.0");
            
            if (conn.getResponseCode() == 200) {
                try (Scanner scanner = new Scanner(conn.getInputStream()).useDelimiter("\\A")) {
                    return scanner.hasNext() ? scanner.next().toLowerCase() : "";
                }
            }
        } catch (Exception e) {
            return null; // Return null to indicate scraping failure
        }
        return null;
    }

    private void applyMitigationRules(String actionLabel, String url, String reason) {
        if (ruleRepository == null || auditLogRepository == null) return; // Prevent NPEs during isolated heuristic testing

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

    private Map<String, Object> buildResponse(String risk, double score, String rating, String finding) {
        Map<String, Object> response = new HashMap<>();
        response.put("riskRating", rating);
        response.put("threatScore", score);
        response.put("summary", finding);
        return response;
    }
}
