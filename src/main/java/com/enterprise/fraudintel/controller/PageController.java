package com.enterprise.fraudintel.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {
    @GetMapping("/")
    public String index() { return "index"; }
    @GetMapping("/login")
    public String login() { return "login"; }
    @GetMapping("/dashboard")
    public String dashboard() { return "dashboard"; }
    @GetMapping("/threat-scan")
    public String threatScan() { return "threat-scan"; }
    @GetMapping("/mitigation-rules")
    public String mitigationRules() { return "mitigation-rules"; }
    @GetMapping("/authorized-users")
    public String authorizedUsers() { return "authorized-users"; }
    @GetMapping("/audit-logs")
    public String auditLogs() { return "audit-logs"; }
}
