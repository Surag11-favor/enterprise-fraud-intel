package com.enterprise.fraudintel.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * Service to maintain connectivity with auxiliary components.
 * Conducting Dual Heartbeat pings every 2 minutes.
 */
@Service
public class HeartbeatService {

    private static final Logger logger = LoggerFactory.getLogger(HeartbeatService.class);
    private final RestTemplate restTemplate;

    @Value("${service.heartfelt-kindness.url:http://heartfelt-kindness.railway.internal}")
    private String heartfeltKindnessUrl;

    @Value("${service.function-bun.url:http://function-bun.railway.internal}")
    private String functionBunUrl;

    public HeartbeatService() {
        this.restTemplate = new RestTemplate();
    }

    @Scheduled(fixedRate = 120000)
    public void sendHeartbeat() {
        logger.info("Initiating Dual Heartbeat Sequence...");
        pingService("HEARTFELT-KINDNESS", heartfeltKindnessUrl + "/actuator/health");
        pingService("FUNCTION-BUN", functionBunUrl + "/actuator/health");
    }

    private void pingService(String name, String url) {
        try {
            logger.info("Pinging {} at {}", name, url);
            restTemplate.getForEntity(url, String.class);
            logger.info("Heartbeat Response: {} is ONLINE", name);
        } catch (Exception e) {
            logger.error("Heartbeat Failure: {} is UNREACHABLE - {}", name, e.getMessage());
        }
    }
}
