package com.enterprise.fraudintel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class EnterpriseFraudApplication {
    public static void main(String[] args) {
        // Cloud Protocol Bridge: Handle Heroku/Railway DATABASE_URL format
        String databaseUrl = System.getenv("DATABASE_URL");
        if (databaseUrl != null && databaseUrl.startsWith("postgres://")) {
            String jdbcUrl = databaseUrl.replace("postgres://", "jdbc:postgresql://");
            System.setProperty("spring.datasource.url", jdbcUrl);
        }
        
        SpringApplication.run(EnterpriseFraudApplication.class, args);
    }
}
