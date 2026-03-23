package com.enterprise.fraudintel.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@RestController
@RequestMapping("/api/analysis")
public class ScanController {

    @PostMapping("/scan")
    public Map<String, Object> runScan(@RequestBody Map<String, String> request) {
        String content = request.get("content");
        
        // Mock analysis logic
        Random random = new Random();
        double riskScore = 10 + (90 * random.nextDouble());
        String riskLevel = riskScore > 75 ? "HIGH" : (riskScore > 40 ? "MEDIUM" : "LOW");
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("riskScore", riskScore);
        response.put("riskLevel", riskLevel);
        response.put("summary", "Analysis complete for payload of length " + (content != null ? content.length() : 0));
        
        return response;
    }
}
