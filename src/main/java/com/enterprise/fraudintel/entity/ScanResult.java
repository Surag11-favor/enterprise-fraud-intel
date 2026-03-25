package com.enterprise.fraudintel.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scan_results")
public class ScanResult {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "TEXT")
    private String payload;

    private Double riskScore;
    private String riskLevel;
    private String socialMediaSentiment; // Requested: "Positive", "Neutral", "Negative"
    
    private LocalDateTime scanTimestamp;

    @PrePersist
    protected void onCreate() {
        scanTimestamp = LocalDateTime.now();
    }

    public ScanResult() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    public Double getRiskScore() { return riskScore; }
    public void setRiskScore(Double riskScore) { this.riskScore = riskScore; }
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public String getSocialMediaSentiment() { return socialMediaSentiment; }
    public void setSocialMediaSentiment(String socialMediaSentiment) { this.socialMediaSentiment = socialMediaSentiment; }
    public LocalDateTime getScanTimestamp() { return scanTimestamp; }
    public void setScanTimestamp(LocalDateTime scanTimestamp) { this.scanTimestamp = scanTimestamp; }
}
