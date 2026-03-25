package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import com.enterprise.fraudintel.repository.ScanResultRepository;
import com.enterprise.fraudintel.repository.UserRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    private final ScanResultRepository scanResultRepository;
    private final MitigationRuleRepository mitigationRuleRepository;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;

    public PageController(ScanResultRepository scanResultRepository, 
                          MitigationRuleRepository mitigationRuleRepository,
                          UserRepository userRepository,
                          AuditLogRepository auditLogRepository) {
        this.scanResultRepository = scanResultRepository;
        this.mitigationRuleRepository = mitigationRuleRepository;
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping("/")
    public String index() { return "index"; }

    @GetMapping("/login")
    public String login() { return "login"; }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        // Professional Stats
        model.addAttribute("activeThreats", scanResultRepository.countByRiskLevel("HIGH"));
        model.addAttribute("blockedThreats", auditLogRepository.countByAction("BLOCK"));
        model.addAttribute("totalScans", scanResultRepository.count());
        model.addAttribute("activeUsers", userRepository.count());
        
        // Activity Feed
        model.addAttribute("recentLogs", auditLogRepository.findAllByOrderByTimestampDesc().stream().limit(5).toList());
        
        return "dashboard";
    }

    @GetMapping("/threat-scan")
    public String threatScan(Model model) {
        model.addAttribute("scans", scanResultRepository.findAllByOrderByScanTimestampDesc());
        return "threat-scan";
    }

    @GetMapping("/mitigation-rules")
    public String mitigationRules(Model model) {
        model.addAttribute("rules", mitigationRuleRepository.findAll());
        return "mitigation-rules";
    }

    @GetMapping("/authorized-users")
    public String authorizedUsers(Model model) {
        model.addAttribute("users", userRepository.findAll());
        return "authorized-users";
    }

    @GetMapping("/audit-logs")
    public String auditLogs(Model model) {
        model.addAttribute("logs", auditLogRepository.findAllByOrderByTimestampDesc());
        return "audit-logs";
    }
}
