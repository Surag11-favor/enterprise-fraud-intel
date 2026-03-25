package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/rules")
public class RuleController {

    private final MitigationRuleRepository ruleRepository;

    public RuleController(MitigationRuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @GetMapping
    public List<MitigationRule> getAllRules() {
        return ruleRepository.findAll();
    }

    @PostMapping
    public MitigationRule createRule(@RequestBody MitigationRule rule) {
        if (rule.getPriority() == null) rule.setPriority(1);
        return ruleRepository.save(rule);
    }

    @PostMapping("/{id}/toggle")
    public ResponseEntity<Void> toggleRule(@PathVariable @org.springframework.lang.NonNull Long id) {
        return ruleRepository.findById(id)
            .map(rule -> {
                rule.setEnabled(!rule.isEnabled());
                ruleRepository.save(rule);
                return ResponseEntity.ok().<Void>build();
            })
            .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRule(@PathVariable @org.springframework.lang.NonNull Long id) {
        ruleRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }
}
