package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.ScanResult;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.ScanResultRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import com.enterprise.fraudintel.service.ScanService;

@RestController
@RequestMapping("/api/analysis")
public class ScanController {

    private final ScanResultRepository scanResultRepository;
    private final AuditLogRepository auditLogRepository;
    private final ScanService scanService;

    public ScanController(ScanResultRepository scanResultRepository, AuditLogRepository auditLogRepository, ScanService scanService) {
        this.scanResultRepository = scanResultRepository;
        this.auditLogRepository = auditLogRepository;
        this.scanService = scanService;
    }

    @PostMapping("/scan")
    public Map<String, Object> runScan(@RequestBody Map<String, String> request, Principal principal) {
        String content = request.get("content");
        
        // Delegate to ScanService for actual detection
        Map<String, Object> analysisResult = scanService.analyzeUrl(content);
        
        String riskRating = (String) analysisResult.get("riskRating");
        double threatScore = (Double) analysisResult.get("threatScore");
        String summary = (String) analysisResult.get("summary");
        
        // Persist Result
        ScanResult result = new ScanResult();
        result.setPayload(content);
        result.setRiskScore(threatScore);
        result.setRiskLevel(riskRating);
        result.setSocialMediaSentiment(summary);
        scanResultRepository.save(result);

        // Audit Log
        AuditLog log = new AuditLog();
        log.setAction("SCAN_PERFORMED");
        log.setPerformedBy(principal != null ? principal.getName() : "Anonymous");
        log.setDetails("Scanned URL: " + (content != null && content.length() > 30 ? content.substring(0, 30) + "..." : content));
        auditLogRepository.save(log);
        
        Map<String, Object> response = new HashMap<>(analysisResult);
        response.put("status", "success");
        
        return response;
    }
}
