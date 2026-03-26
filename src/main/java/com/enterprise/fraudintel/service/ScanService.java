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

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "bid", "pw", "buzz",
        "click", "rest", "cam", "icu", "work", "live", "su", "cc", "ws", "info"
    );

    private static final Set<String> DECEPTIVE_KEYWORDS = Set.of(
        "login", "verify", "secure", "account", "update", "signin", "banking",
        "support", "billing", "confirm", "validate", "authenticate", "password",
        "suspend", "locked", "unusual", "expire", "urgent", "alert", "warning"
    );

    private static final Set<String> SOCIAL_MEDIA_BRANDS = Set.of(
        "facebook", "twitter", "instagram", "tiktok", "linkedin", "snapchat",
        "youtube", "whatsapp", "telegram", "paypal", "netflix", "amazon",
        "apple", "microsoft", "google", "dropbox", "spotify", "steam", "discord"
    );

    // Typosquatting variants: common letter-to-number and letter swaps
    private static final Map<Character, List<Character>> TYPO_MAP = Map.ofEntries(
        Map.entry('a', List.of('4', '@')),
        Map.entry('e', List.of('3')),
        Map.entry('i', List.of('1', '!')),
        Map.entry('o', List.of('0')),
        Map.entry('s', List.of('5', '$')),
        Map.entry('t', List.of('7')),
        Map.entry('l', List.of('1')),
        Map.entry('b', List.of('8'))
    );

    private static final Set<String> SHORTENER_DOMAINS = Set.of(
        "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly",
        "rebrand.ly", "rb.gy", "cutt.ly", "shorturl.at", "v.gd", "goo.gl",
        "tiny.cc", "bc.vc", "urlz.fr"
    );

    private static final Set<String> SOCIAL_SCAM_KEYWORDS = Set.of(
        "giveaway", "free followers", "followers", "nft raffle", "crypto gift",
        "claim", "hack", "disabled", "winner", "prize", "congratulations",
        "selected", "reward", "airdrop", "earn money", "click here"
    );

    public Map<String, Object> analyzeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return buildResponse("LOW", 0.0, "Empty payload provided.", new ArrayList<>());
        }

        String url = rawUrl.trim().toLowerCase();
        double totalScore = 0.0;
        List<String> findings = new ArrayList<>();

        // ═══════════ PHASE 1: URL SURFACE ANALYSIS ═══════════

        // 1.1 URL Shortener Detection
        boolean isShortened = false;
        for (String shortener : SHORTENER_DOMAINS) {
            if (url.contains(shortener)) {
                isShortened = true;
                totalScore += 30.0;  // Shorteners hide real destination — high suspicion
                findings.add("URL Shortener detected (" + shortener + ") — destination is masked");
                break;
            }
        }

        // 1.2 If shortened, try to follow redirects to get the real URL
        String resolvedUrl = url;
        if (isShortened) {
            String followed = followRedirects(url);
            if (followed != null && !followed.equals(url)) {
                resolvedUrl = followed.toLowerCase();
                findings.add("Redirect resolved to: " + (resolvedUrl.length() > 60 ? resolvedUrl.substring(0, 60) + "..." : resolvedUrl));
                // Now analyze the REAL destination URL too
            } else {
                totalScore += 20.0;
                findings.add("Shortened URL redirect could NOT be resolved — high evasion risk");
            }
        }

        // 1.3 Deceptive Keyword Heuristics (check both original and resolved URL)
        Set<String> foundKeywords = new HashSet<>();
        for (String keyword : DECEPTIVE_KEYWORDS) {
            if (url.contains(keyword) || resolvedUrl.contains(keyword)) {
                foundKeywords.add(keyword);
            }
        }
        if (!foundKeywords.isEmpty()) {
            totalScore += Math.min(foundKeywords.size() * 12.0, 40.0);
            findings.add("Deceptive keywords identified: " + String.join(", ", foundKeywords));
        }

        // 1.4 Protocol Layer
        if (!url.startsWith("https://") && !url.startsWith("https")) {
            totalScore += 25.0;
            findings.add("Non-HTTPS protocol — data transmitted in cleartext");
        }

        // ═══════════ PHASE 2: DOMAIN INTELLIGENCE ═══════════
        try {
            String urlToParse = resolvedUrl.startsWith("http") ? resolvedUrl : "https://" + resolvedUrl;
            URL parsedUrl = URI.create(urlToParse).toURL();
            String host = parsedUrl.getHost();
            String path = parsedUrl.getPath();

            if (host == null || host.isEmpty()) {
                totalScore += 30.0;
                findings.add("Invalid or missing hostname — severely malformed URL");
            } else {
                String[] parts = host.split("\\.");
                String domain = parts.length >= 2 ? parts[parts.length - 2] : host;
                String tld = parts.length >= 1 ? parts[parts.length - 1] : "";
                String fullDomain = domain + "." + tld;

                // 2.1 TLD Reputation
                if (SUSPICIOUS_TLDS.contains(tld)) {
                    totalScore += 25.0;
                    findings.add("High-risk TLD registered (." + tld + ") — commonly used in phishing");
                }

                // 2.2 Domain Entropy (randomness)
                double domainEntropy = calculateEntropy(domain);
                if (domainEntropy > 4.0) {
                    totalScore += 15.0;
                    findings.add("High entropy domain (score: " + String.format("%.2f", domainEntropy) + ") — possible Domain Generation Algorithm");
                }

                // 2.3 TYPOSQUATTING DETECTION — the critical fix
                for (String brand : SOCIAL_MEDIA_BRANDS) {
                    // Exact match
                    if (host.contains(brand) && !host.equals(brand + ".com") && !host.equals("www." + brand + ".com")) {
                        totalScore += 35.0;
                        findings.add("Brand impersonation: \"" + brand + "\" found in non-official domain " + host);
                        break;
                    }
                    // Typosquatting/Leetspeak match
                    if (isTyposquat(domain, brand) || isTyposquat(host, brand)) {
                        totalScore += 45.0;
                        findings.add("TYPOSQUATTING DETECTED: \"" + domain + "\" appears to impersonate \"" + brand + "\" using character substitution");
                        break;
                    }
                }

                // 2.4 Subdomain depth (evasion technique)
                if (parts.length > 3) {
                    totalScore += 12.0;
                    findings.add("Excessive subdomain depth (" + parts.length + " levels) — domain obfuscation");
                }

                // 2.5 IP-based hosting
                if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                    totalScore += 25.0;
                    findings.add("Direct IP hosting — bypasses DNS reputation systems");
                }

                // 2.6 Hyphen abuse in domain
                long hyphenCount = domain.chars().filter(c -> c == '-').count();
                if (hyphenCount >= 2) {
                    totalScore += 15.0;
                    findings.add("Multiple hyphens in domain (" + hyphenCount + ") — common phishing pattern");
                }

                // 2.7 Domain length
                if (domain.length() > 20) {
                    totalScore += 10.0;
                    findings.add("Unusually long domain name (" + domain.length() + " chars)");
                }

                // 2.8 Path analysis
                if (path != null && !path.isEmpty()) {
                    if (path.contains("..") || path.contains("%2e%2e") || path.contains("%252e")) {
                        totalScore += 30.0;
                        findings.add("Path traversal attack pattern detected");
                    }
                    if (path.contains(".php") || path.contains(".asp") || path.contains("wp-login") || path.contains("wp-admin")) {
                        totalScore += 10.0;
                        findings.add("Server-side endpoint exposure in URL path");
                    }
                    String[] pathParts = path.split("/");
                    if (pathParts.length > 6) {
                        totalScore += 5.0;
                        findings.add("Deep URL path structure (" + pathParts.length + " segments)");
                    }
                }

                // ═══════════ PHASE 3: LIVE CONTENT ANALYSIS ═══════════
                String pageContent = fetchPageContent(urlToParse);
                if (pageContent != null && !pageContent.isEmpty()) {
                    int contentLength = pageContent.length();
                    findings.add("Live page fetched (" + (contentLength / 1024) + " KB) — performing deep content analysis");

                    // 3.1 Script obfuscation
                    if (pageContent.contains("eval(") || pageContent.contains("document.write(unescape(") || pageContent.contains("eval(unescape(")) {
                        totalScore += 35.0;
                        findings.add("Malicious script obfuscation detected (eval/unescape patterns)");
                    }

                    // 3.2 Base64 encoded payloads
                    if (pageContent.contains("atob(") || pageContent.contains("btoa(") || pageContent.contains("base64")) {
                        totalScore += 12.0;
                        findings.add("Base64 encoding functions detected — possible payload concealment");
                    }

                    // 3.3 Credential harvesting forms
                    if (pageContent.contains("<form")) {
                        boolean hasCredentialFields = pageContent.contains("password") || pageContent.contains("credit") || pageContent.contains("ssn") || pageContent.contains("card-number") || pageContent.contains("cvv");
                        if (hasCredentialFields) {
                            totalScore += 30.0;
                            findings.add("CREDENTIAL HARVESTING: Form with sensitive input fields detected");
                        }
                    }

                    // 3.4 Hidden elements
                    int hiddenCount = 0;
                    if (pageContent.contains("display:none")) hiddenCount++;
                    if (pageContent.contains("visibility:hidden")) hiddenCount++;
                    if (pageContent.contains("opacity:0")) hiddenCount++;
                    if (pageContent.contains("height:0")) hiddenCount++;
                    if (hiddenCount >= 2) {
                        totalScore += 15.0;
                        findings.add("Multiple hidden DOM elements (" + hiddenCount + " patterns) — stealth payload indicators");
                    }

                    // 3.5 Auto-redirect detection
                    if (pageContent.contains("meta http-equiv=\"refresh\"") || pageContent.contains("window.location") || pageContent.contains("location.replace") || pageContent.contains("location.href")) {
                        totalScore += 15.0;
                        findings.add("Automatic redirect mechanism embedded in page");
                    }

                    // 3.6 Social scam keywords in content
                    long scamMatches = SOCIAL_SCAM_KEYWORDS.stream().filter(pageContent::contains).count();
                    if (scamMatches >= 3) {
                        totalScore += (8.0 * scamMatches);
                        findings.add("High density of social scam keywords in content (" + scamMatches + " matches)");
                    }

                    // 3.7 Suspicious external resources
                    for (String susTld : SUSPICIOUS_TLDS) {
                        if (pageContent.contains("src=\"") && (pageContent.contains("." + susTld + "/") || pageContent.contains("." + susTld + "\""))) {
                            totalScore += 20.0;
                            findings.add("External resources loaded from high-risk TLD (." + susTld + ")");
                            break;
                        }
                    }

                    // 3.8 Script & iframe density
                    int scriptCount = countOccurrences(pageContent, "<script");
                    int iframeCount = countOccurrences(pageContent, "<iframe");
                    if (scriptCount > 10) {
                        totalScore += 8.0;
                        findings.add("High script density (" + scriptCount + " script tags)");
                    }
                    if (iframeCount > 2) {
                        totalScore += 12.0;
                        findings.add("Multiple iframe embeds (" + iframeCount + " detected)");
                    }

                } else {
                    // Content couldn't be fetched
                    if (totalScore > 25) {
                        totalScore += 15.0;
                        findings.add("Target page unreachable — suspicious for already-flagged URL (possible evasion)");
                    } else {
                        findings.add("Target content could not be retrieved for deep analysis");
                    }
                }
            }

        } catch (Exception e) {
            totalScore += 30.0;
            findings.add("URL parsing failed — severely malformed or hostile target: " + e.getMessage());
        }

        // ═══════════ PHASE 4: FINAL VERDICT ═══════════
        double finalScore = Math.min(totalScore, 100.0);
        String riskLevel;
        if (finalScore >= 65.0) {
            riskLevel = "HIGH";
        } else if (finalScore >= 35.0) {
            riskLevel = "MEDIUM";
        } else {
            riskLevel = "LOW";
        }

        String summaryText;
        if (findings.isEmpty()) {
            summaryText = "All heuristic checks passed. URL appears safe.";
        } else {
            summaryText = findings.size() + " findings detected through multi-layer analysis. Verdict: " + riskLevel + ".";
        }

        try {
            applyMitigationRules(riskLevel.equals("HIGH") ? "BLOCK" : (riskLevel.equals("MEDIUM") ? "CHALLENGE" : "NONE"), rawUrl, String.join(", ", findings));
        } catch (Exception ignored) {}

        return buildResponse(riskLevel, finalScore, summaryText, findings);
    }

    /**
     * Typosquatting detection: Normalizes leetspeak/character substitutions
     * and checks if the result matches a known brand.
     * e.g., "faceb00k" → "facebook", "g00gle" → "google", "4mazon" → "amazon"
     */
    private boolean isTyposquat(String suspect, String brand) {
        if (suspect == null || brand == null) return false;
        
        // Remove hyphens and dots for comparison
        String cleaned = suspect.replace("-", "").replace(".", "");
        
        // Normalize leetspeak: replace all substitution characters back to letters
        StringBuilder normalized = new StringBuilder();
        for (char c : cleaned.toCharArray()) {
            boolean replaced = false;
            for (Map.Entry<Character, List<Character>> entry : TYPO_MAP.entrySet()) {
                if (entry.getValue().contains(c)) {
                    normalized.append(entry.getKey());
                    replaced = true;
                    break;
                }
            }
            if (!replaced) {
                normalized.append(c);
            }
        }

        String normalizedStr = normalized.toString();

        // Check if normalized version contains or equals the brand
        if (normalizedStr.contains(brand)) return true;

        // Check Levenshtein distance (allow 1-2 edits for typos like facebok, gooogle)
        if (brand.length() >= 5) {
            int distance = levenshteinDistance(normalizedStr, brand);
            if (distance <= 2 && distance > 0) return true;
            
            // Also check if the cleaned (non-normalized) version is close
            int rawDistance = levenshteinDistance(cleaned, brand);
            if (rawDistance <= 2 && rawDistance > 0) return true;
        }

        return false;
    }

    /**
     * Levenshtein distance for typo detection
     */
    private int levenshteinDistance(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;
        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
            }
        }
        return dp[a.length()][b.length()];
    }

    /**
     * Follow redirects on shortened URLs to discover the real destination
     */
    private String followRedirects(String urlString) {
        try {
            String normalizedUrl = urlString.startsWith("http") ? urlString : "https://" + urlString;
            HttpURLConnection conn = (HttpURLConnection) URI.create(normalizedUrl).toURL().openConnection();
            conn.setRequestMethod("HEAD");
            conn.setInstanceFollowRedirects(false); // Don't auto-follow — we want to see each hop
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

            int status = conn.getResponseCode();
            if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                String location = conn.getHeaderField("Location");
                if (location != null && !location.isEmpty()) {
                    return location;
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private String fetchPageContent(String urlString) {
        try {
            String normalizedUrl = urlString.startsWith("http") ? urlString : "https://" + urlString;
            HttpURLConnection conn = (HttpURLConnection) URI.create(normalizedUrl).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Enterprise-Threat-Intel/1.0");

            if (conn.getResponseCode() == 200) {
                try (Scanner scanner = new Scanner(conn.getInputStream()).useDelimiter("\\A")) {
                    String content = scanner.hasNext() ? scanner.next().toLowerCase() : "";
                    // Limit content to first 500KB to avoid memory issues
                    return content.length() > 512000 ? content.substring(0, 512000) : content;
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private void applyMitigationRules(String actionLabel, String url, String reason) {
        if (ruleRepository == null || auditLogRepository == null) return;

        List<MitigationRule> activeRules = ruleRepository.findAll().stream()
            .filter(MitigationRule::isEnabled)
            .filter(r -> r.getAction() != null && r.getAction().equalsIgnoreCase(actionLabel))
            .toList();

        if (!activeRules.isEmpty()) {
            AuditLog log = new AuditLog();
            log.setAction(actionLabel);
            log.setPerformedBy("SYSTEM-ENGINE");
            String truncatedReason = reason.length() > 200 ? reason.substring(0, 200) : reason;
            log.setDetails(actionLabel + " applied. Reason: " + truncatedReason);
            auditLogRepository.save(log);
        }
    }

    private double calculateEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.put(c, freq.getOrDefault(c, 0) + 1);
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = (double) count / s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private int countOccurrences(String text, String pattern) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(pattern, idx)) != -1) {
            count++;
            idx += pattern.length();
        }
        return count;
    }

    private Map<String, Object> buildResponse(String riskLevel, double score, String summary, List<String> findings) {
        Map<String, Object> response = new HashMap<>();
        response.put("riskRating", riskLevel);
        response.put("threatScore", score);
        response.put("summary", summary);
        response.put("findings", findings != null ? findings : new ArrayList<>());
        return response;
    }
}
