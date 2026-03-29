package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import com.enterprise.fraudintel.repository.ScanResultRepository;
import com.enterprise.fraudintel.repository.UserRepository;
import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.entity.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class PageController {

    private final ScanResultRepository scanResultRepository;
    private final MitigationRuleRepository mitigationRuleRepository;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final PasswordEncoder passwordEncoder;

    public PageController(ScanResultRepository scanResultRepository, 
                          MitigationRuleRepository mitigationRuleRepository,
                          UserRepository userRepository,
                          AuditLogRepository auditLogRepository,
                          PasswordEncoder passwordEncoder) {
        this.scanResultRepository = scanResultRepository;
        this.mitigationRuleRepository = mitigationRuleRepository;
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.passwordEncoder = passwordEncoder;
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

    @PostMapping("/rules/add")
    public String addRule(MitigationRule rule) {
        if (rule.getPriority() == null) rule.setPriority(1);
        mitigationRuleRepository.save(rule);
        return "redirect:/mitigation-rules";
    }

    @GetMapping("/rules/delete/{id}")
    public String deleteRule(@PathVariable Long id) {
        mitigationRuleRepository.deleteById(id);
        return "redirect:/mitigation-rules";
    }

    @PostMapping("/authorized-users/add")
    public String addUser(User user) {
        if (userRepository.findByUsername(user.getUsername()).isEmpty()) {
            String rawPassword = (user.getPassword() != null && !user.getPassword().isEmpty()) 
                ? user.getPassword() : "password123";
            user.setPassword(passwordEncoder.encode(rawPassword));
            if (user.getRole() == null || user.getRole().isEmpty()) user.setRole("USER");
            userRepository.save(user);
        }
        return "redirect:/authorized-users";
    }

    @GetMapping("/authorized-users/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return "redirect:/authorized-users";
    }

    @PostMapping("/threat-scan")
    public String performScan() {
        return "redirect:/threat-scan";
    }
}
