package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.ScanResult;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.ScanResultRepository;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.*;
import com.enterprise.fraudintel.service.ScanService;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanResultRepository scanResultRepository;
    private final AuditLogRepository auditLogRepository;
    private final ScanService scanService;

    public ScanController(ScanResultRepository scanResultRepository, AuditLogRepository auditLogRepository, ScanService scanService) {
        this.scanResultRepository = scanResultRepository;
        this.auditLogRepository = auditLogRepository;
        this.scanService = scanService;
    }

    @PostMapping("/scans/analyze")
    public Map<String, Object> runScan(@RequestParam("payload") String payload, Principal principal) {
        try {
            Map<String, Object> analysisResult = scanService.analyzeUrl(payload);

            String riskRating = String.valueOf(analysisResult.get("riskRating"));
            Object scoreObj = analysisResult.get("threatScore");
            double threatScore = scoreObj instanceof Number ? ((Number) scoreObj).doubleValue() : 0.0;
            String summary = String.valueOf(analysisResult.get("summary"));

            // Truncate summary for DB storage
            String dbSummary = summary.length() > 250 ? summary.substring(0, 250) : summary;

            ScanResult result = new ScanResult();
            result.setPayload(payload);
            result.setRiskScore(threatScore);
            result.setRiskLevel(riskRating);
            result.setSocialMediaSentiment(dbSummary);
            scanResultRepository.save(result);

            AuditLog log = new AuditLog();
            log.setAction("SCAN_PERFORMED");
            log.setPerformedBy(principal != null ? principal.getName() : "Anonymous");
            log.setDetails("Scanned: " + (payload.length() > 30 ? payload.substring(0, 30) + "..." : payload) + " | " + riskRating + " " + threatScore + "%");
            auditLogRepository.save(log);

            Map<String, Object> response = new HashMap<>(analysisResult);
            response.put("status", "success");
            return response;

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("riskRating", "HIGH");
            errorResponse.put("threatScore", 95.0);
            errorResponse.put("summary", "Analysis engine encountered a critical error during scan.");
            errorResponse.put("findings", List.of("Internal scan error: " + e.getMessage()));
            return errorResponse;
        }
    }
}
