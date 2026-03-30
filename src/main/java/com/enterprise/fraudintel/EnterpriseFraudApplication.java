package com.enterprise.fraudintel;

import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.entity.User;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import com.enterprise.fraudintel.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;
import java.net.URISyntaxException;

@SpringBootApplication
public class EnterpriseFraudApplication {
    public static void main(String[] args) {
        // Cloud Protocol Bridge: Handle Heroku/Railway DATABASE_URL format
        String databaseUrl = System.getenv("DATABASE_URL");
        if (databaseUrl != null && databaseUrl.startsWith("postgres://")) {
            try {
                URI uri = new URI(databaseUrl);
                String userInfo = uri.getUserInfo();
                if (userInfo != null) {
                    String[] userParts = userInfo.split(":");
                    System.setProperty("CUSTOM_DB_USER", userParts[0]);
                    if (userParts.length > 1) {
                        System.setProperty("CUSTOM_DB_PASS", userParts[1]);
                    }
                }
                
                String port = uri.getPort() == -1 ? "5432" : String.valueOf(uri.getPort());
                String dbUrl = "jdbc:postgresql://" + uri.getHost() + ":" + port + uri.getPath() + "?sslmode=require";
                System.setProperty("CUSTOM_JDBC_URL", dbUrl);
                
                System.out.println("DATABASE_URL Handshake: SECURED");
            } catch (URISyntaxException e) {
                System.err.println("DATABASE_URL Handshake: FAILED - " + e.getMessage());
            }
        }
        
        SpringApplication.run(EnterpriseFraudApplication.class, args);
    }

    @Bean
    public CommandLineRunner initData(MitigationRuleRepository ruleRepo, UserRepository userRepo, PasswordEncoder encoder) {
        return args -> {
            // Seed default admin if none exists
            if (userRepo.findByUsername("admin").isEmpty()) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(encoder.encode("admin123"));
                admin.setRole("ADMIN");
                userRepo.save(admin);
            }

            // Seed professional mitigation rules if empty
            if (ruleRepo.count() == 0) {
                saveRule(ruleRepo, "PROTOCOL_SHIELD_V4", "Deep-packet inspection and protocol anomaly detection across Zone-1.", "BLOCK");
                saveRule(ruleRepo, "NEURAL_VECTOR_CHALLENGE", "Invokes multi-factor CAPTCHA challenge for suspicious ingress traffic.", "CHALLENGE");
                saveRule(ruleRepo, "REPUTATION_BARRIER", "Automatic blacklisting of known threat-actor TLDs (.xyz, .top, .ml).", "BLOCK");
                saveRule(ruleRepo, "CREDENTIAL_SENTRY", "Monitors and randomizes authentication tokens during brute-force detection.", "CHALLENGE");
                saveRule(ruleRepo, "HEURISTIC_NULLIFY", "Force-terminates requests featuring obfuscated Javascript payloads.", "BLOCK");
            }
        };
    }

    private void saveRule(MitigationRuleRepository repo, String name, String desc, String action) {
        MitigationRule rule = new MitigationRule();
        rule.setName(name);
        rule.setDescription(desc);
        rule.setAction(action);
        rule.setEnabled(false); // Default to off so 'Fix All' can activate them
        rule.setPriority(1);
        repo.save(rule);
    }
}
