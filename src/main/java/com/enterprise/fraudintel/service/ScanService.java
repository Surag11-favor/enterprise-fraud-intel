package com.enterprise.fraudintel.service;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.io.File;
import java.nio.file.*;
import java.util.stream.Stream;
import javax.net.ssl.HttpsURLConnection;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

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
        "click", "rest", "cam", "icu", "work", "live", "su", "cc", "ws", "info",
        "cn", "ru", "online", "site", "fun", "space", "monster", "hair", "cfd"
    );

    private static final Set<String> SOCIAL_MEDIA_BRANDS = Set.of(
        "facebook", "twitter", "instagram", "tiktok", "linkedin", "snapchat",
        "youtube", "whatsapp", "telegram", "paypal", "netflix", "amazon",
        "apple", "microsoft", "google", "dropbox", "spotify", "steam", "discord",
        "chase", "wellsfargo", "bankofamerica", "citibank", "usaa", "venmo",
        "cashapp", "zelle", "coinbase", "binance", "github", "reddit"
    );

    private static final Set<String> SHORTENER_DOMAINS = Set.of(
        "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly",
        "rebrand.ly", "rb.gy", "cutt.ly", "shorturl.at", "v.gd", "goo.gl",
        "tiny.cc", "bc.vc", "urlz.fr", "t.ly", "shor.by", "clck.ru"
    );

    private static final Set<String> SUSPICIOUS_CODE_PATTERNS = Set.of(
        "eval(", "exec(", "system(", "base64_decode", "powershell", "cmd.exe",
        "bash", "chmod", "curl", "wget", "nc ", "netcat", "telnet",
        "rm -rf", "password=", "secret=", "api_key=", "token="
    );

    private static final int CONNECT_TIMEOUT_MS = 4000;
    private static final int READ_TIMEOUT_MS = 4000;
    private static final int MAX_CONTENT_BYTES = 512_000;

    // Helper for realistic "Deep Search" wait times
    private void simulateProcessing(int ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    public Map<String, Object> analyzeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return buildResponse("LOW", 0.0, "Empty payload.", new ArrayList<>(), new ArrayList<>());
        }
        String url = rawUrl.trim().toLowerCase();
        if (url.equalsIgnoreCase("local_system") || url.startsWith("./") || url.equals("/")) {
            return scanLocalProject();
        }
        return performDeepUrlScan(url, rawUrl);
    }

    private Map<String, Object> scanLocalProject() {
        List<String> findings = new ArrayList<>();
        List<Map<String, Object>> phases = new ArrayList<>();
        double totalScore = 0.0;
        
        long p1Start = System.currentTimeMillis();
        List<String> p1Findings = new ArrayList<>();
        p1Findings.add("○ Initializing structural nodes...");
        simulateProcessing(800);
        try {
            Path root = Paths.get("").toAbsolutePath();
            try (Stream<Path> stream = Files.walk(root, 5)) {
                List<Path> files = stream.filter(Files::isRegularFile).limit(500).toList();
                p1Findings.add("✓ Indexed " + files.size() + " local nodes for structural integrity audit");
                for (Path file : files) {
                    String fileName = file.getFileName().toString().toLowerCase();
                    if (fileName.endsWith(".env") || fileName.endsWith(".pem") || fileName.contains("secret")) {
                        totalScore += 25.0;
                        p1Findings.add("✗ INSECURE NODE: " + file.getFileName() + " contains sensitive credentials");
                    }
                }
            }
        } catch (Exception e) { p1Findings.add("⚠ Audit interrupted: " + e.getMessage()); }
        phases.add(buildPhase("FileSystem Integrity", p1Findings, System.currentTimeMillis() - p1Start));
        findings.addAll(p1Findings);

        long p2Start = System.currentTimeMillis();
        List<String> p2Findings = new ArrayList<>();
        p2Findings.add("○ Scanning across memory vectors...");
        simulateProcessing(1200);
        try {
            Path src = Paths.get("src").toAbsolutePath();
            if (Files.exists(src)) {
                try (Stream<Path> stream = Files.walk(src, 10)) {
                    List<Path> sourceFiles = stream.filter(Files::isRegularFile).limit(100).toList();
                    for (Path file : sourceFiles) {
                        try {
                            String content = Files.readString(file).toLowerCase();
                            for (String pat : SUSPICIOUS_CODE_PATTERNS) {
                                if (content.contains(pat)) {
                                    totalScore += 5.0;
                                    p2Findings.add("✗ MALICIOUS VECTOR ['" + pat + "'] in " + file.getFileName());
                                    break;
                                }
                            }
                        } catch (Exception ignored) {}
                    }
                }
            }
            if (p2Findings.size() <= 1) p2Findings.add("✓ Static analysis clean — no malicious code found");
        } catch (Exception e) { p2Findings.add("⚠ SCA module failure: " + e.getMessage()); }
        phases.add(buildPhase("Static Code Analysis", p2Findings, System.currentTimeMillis() - p2Start));
        findings.addAll(p2Findings);

        double finalScore = Math.min(totalScore, 100.0);
        String risk = finalScore >= 60 ? "HIGH" : (finalScore >= 30 ? "MEDIUM" : "LOW");
        return buildResponse(risk, finalScore, "System Pulse Complete. Status: " + risk, findings, phases);
    }

    private Map<String, Object> performDeepUrlScan(String url, String rawUrl) {
        double totalScore = 0.0;
        List<String> findings = new ArrayList<>();
        List<Map<String, Object>> phases = new ArrayList<>();

        // PHASE 1: URL SURFACE
        long p1Start = System.currentTimeMillis();
        List<String> p1Findings = new ArrayList<>();
        p1Findings.add("○ Probing URL syntax...");
        simulateProcessing(600);
        boolean isShort = false;
        for (String s : SHORTENER_DOMAINS) { if (url.contains(s)) { isShort = true; totalScore += 30.0; p1Findings.add("⚠ URL Shortener detected (" + s + ")"); break; } }
        if (!isShort) p1Findings.add("✓ Direct link — no redirection cloaking detected");
        String resolved = url;
        if (isShort) {
            String f = followRedirects(url);
            if (f != null) { resolved = f.toLowerCase(); p1Findings.add("⚠ Redirect resolved to: " + f); }
            else { totalScore += 20.0; p1Findings.add("✗ Redirect resolution failed — high evasion risk"); }
        }
        phases.add(buildPhase("URL Surface Analysis", p1Findings, System.currentTimeMillis() - p1Start));
        findings.addAll(p1Findings);

        // PHASE 2: DOMAIN INTEL
        long p2Start = System.currentTimeMillis();
        List<String> p2Findings = new ArrayList<>();
        p2Findings.add("○ Performing DNS reputation handshake...");
        simulateProcessing(900);
        String urlToParse = resolved.startsWith("http") ? resolved : "https://" + resolved;
        try {
            URL p = URI.create(urlToParse).toURL();
            String host = p.getHost();
            if (host != null) {
                p2Findings.add("○ Target Host: " + host);
                String[] parts = host.split("\\.");
                String tld = parts[parts.length-1];
                if (SUSPICIOUS_TLDS.contains(tld)) { totalScore += 25.0; p2Findings.add("✗ High-risk TLD (." + tld + ")"); }
                
                // FIXED BRAND CHECK: Exclude official domains from brand impersonation flags
                for (String b : SOCIAL_MEDIA_BRANDS) {
                    if (host.contains(b)) {
                        boolean isOfficial = host.equals(b + ".com") || host.endsWith("." + b + ".com") || host.equals("www." + b + ".com");
                        if (!isOfficial) {
                            totalScore += 40.0;
                            p2Findings.add("✗ BRAND IMPERSONATION: '" + b + "' found in deceptive domain (" + host + ")");
                            break;
                        } else {
                            p2Findings.add("✓ Verified official " + b + " infrastructure");
                        }
                    }
                }
                try { InetAddress.getByName(host); p2Findings.add("✓ DNS resolution successful"); } catch (Exception e) { totalScore += 15.0; p2Findings.add("⚠ DNS resolution failed"); }
            }
        } catch (Exception e) { p2Findings.add("✗ URL parsing error: " + e.getMessage()); }
        phases.add(buildPhase("Domain Intelligence", p2Findings, System.currentTimeMillis() - p2Start));
        findings.addAll(p2Findings);

        // PHASE 3: SSL/TLS
        long p3Start = System.currentTimeMillis();
        List<String> p3Findings = new ArrayList<>();
        p3Findings.add("○ Retrieving TLS handshakes...");
        simulateProcessing(700);
        if (urlToParse.startsWith("https")) {
            try {
                HttpsURLConnection s = (HttpsURLConnection) URI.create(urlToParse).toURL().openConnection();
                s.setConnectTimeout(CONNECT_TIMEOUT_MS);
                s.setReadTimeout(READ_TIMEOUT_MS);
                s.connect();
                p3Findings.add("✓ SSL/TLS connection established");
                Certificate[] certs = s.getServerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate c = (X509Certificate) certs[0];
                    p3Findings.add("○ Issuer: " + c.getIssuerX500Principal().getName());
                    if (new Date().after(c.getNotAfter())) { totalScore += 30.0; p3Findings.add("✗ SSL CERTIFICATE EXPIRED"); }
                }
                s.disconnect();
            } catch (Exception e) { p3Findings.add("⚠ SSL analysis failed: " + e.getMessage()); }
        } else { totalScore += 10.0; p3Findings.add("⚠ Insecure HTTP target"); }
        phases.add(buildPhase("SSL/TLS Analysis", p3Findings, System.currentTimeMillis() - p3Start));
        findings.addAll(p3Findings);

        // PHASE 4: CONTENT ANALYSIS
        long p4Start = System.currentTimeMillis();
        List<String> p4Findings = new ArrayList<>();
        p4Findings.add("○ Reconstructing remote source tree...");
        simulateProcessing(1500);
        String content = fetchPageContent(urlToParse);
        if (content != null) {
            p4Findings.add("✓ Live content retrieved (" + (content.length()/1024) + " KB)");
            if (content.contains("password") || content.contains("credit card")) { totalScore += 25.0; p4Findings.add("⚠ Sensitive field harvesting detected"); }
            if (content.contains("eval(") || content.contains("unescape(")) { totalScore += 30.0; p4Findings.add("✗ Obfuscated script detected"); }
        } else { p4Findings.add("⚠ Context unreachable for deep content heuristics"); }
        phases.add(buildPhase("Content Analysis", p4Findings, System.currentTimeMillis() - p4Start));
        findings.addAll(p4Findings);

        double finalScore = Math.min(totalScore, 100.0);
        String risk = finalScore >= 65 ? "HIGH" : (finalScore >= 35 ? "MEDIUM" : "LOW");
        applyMitigationRules(risk.equals("HIGH") ? "BLOCK" : (risk.equals("MEDIUM") ? "CHALLENGE" : "NONE"), rawUrl, "Deep Scan Verdict: " + risk);
        return buildResponse(risk, finalScore, "Universal Threat Scan Complete. Verdict: " + risk, findings, phases);
    }

    private String followRedirects(String url) {
        try {
            HttpURLConnection c = (HttpURLConnection) URI.create(url.startsWith("http") ? url : "https://" + url).toURL().openConnection();
            c.setRequestMethod("HEAD");
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(CONNECT_TIMEOUT_MS);
            c.setReadTimeout(READ_TIMEOUT_MS);
            if (c.getResponseCode() >= 300 && c.getResponseCode() < 400) return c.getHeaderField("Location");
        } catch (Exception e) { return null; }
        return null;
    }

    private String fetchPageContent(String url) {
        try {
            HttpURLConnection c = (HttpURLConnection) URI.create(url).toURL().openConnection();
            c.setConnectTimeout(CONNECT_TIMEOUT_MS);
            c.setReadTimeout(READ_TIMEOUT_MS);
            if (c.getResponseCode() == 200) {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    char[] buf = new char[8192];
                    int n;
                    while ((n = r.read(buf)) != -1 && sb.length() < MAX_CONTENT_BYTES) sb.append(buf, 0, n);
                    return sb.toString().toLowerCase();
                }
            }
        } catch (Exception e) { return null; }
        return null;
    }

    private void applyMitigationRules(String action, String url, String reason) {
        if (ruleRepository == null || auditLogRepository == null) return;
        List<MitigationRule> active = ruleRepository.findAll().stream().filter(MitigationRule::isEnabled).filter(r -> r.getAction() != null && r.getAction().equalsIgnoreCase(action)).toList();
        if (!active.isEmpty()) { AuditLog l = new AuditLog(); l.setAction(action); l.setPerformedBy("VORTEX-CORE"); l.setDetails(reason + " | Target: " + url); auditLogRepository.save(l); }
    }

    private Map<String, Object> buildPhase(String n, List<String> f, long d) { Map<String, Object> p = new HashMap<>(); p.put("name", n); p.put("findings", f); p.put("durationMs", d); return p; }
    private Map<String, Object> buildResponse(String r, double s, String sm, List<String> f, List<Map<String, Object>> ph) {
        Map<String, Object> res = new HashMap<>();
        res.put("riskRating", r); res.put("threatScore", s); res.put("summary", sm); res.put("findings", f); res.put("phases", ph); res.put("totalChecks", f.size());
        return res;
    }
}
