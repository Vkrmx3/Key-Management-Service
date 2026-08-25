package com.keymanagement.dto;

import java.time.LocalDateTime;

/**
 * Response DTO for key version information.
 */
public class KeyVersionInfo {

    private String keyId;
    private String logicalKeyId;
    private Integer version;
    private Boolean currentVersion;
    private String algorithm;
    private Integer keySize;
    private LocalDateTime createdAt;
    private LocalDateTime rotatedAt;
    private String rotationReason;
    private Boolean active;

    // Constructors
    public KeyVersionInfo() {
    }

    // Getters and Setters
    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getLogicalKeyId() {
        return logicalKeyId;
    }

    public void setLogicalKeyId(String logicalKeyId) {
        this.logicalKeyId = logicalKeyId;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public Boolean getCurrentVersion() {
        return currentVersion;
    }

    public void setCurrentVersion(Boolean currentVersion) {
        this.currentVersion = currentVersion;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getRotatedAt() {
        return rotatedAt;
    }

    public void setRotatedAt(LocalDateTime rotatedAt) {
        this.rotatedAt = rotatedAt;
    }

    public String getRotationReason() {
        return rotationReason;
    }

    public void setRotationReason(String rotationReason) {
        this.rotationReason = rotationReason;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}
