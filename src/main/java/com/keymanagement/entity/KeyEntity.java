package com.keymanagement.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * JPA Entity for storing encryption keys in the database.
 * Supports key versioning for rotation.
 * 
 * Key Versioning:
 * - logicalKeyId: The stable identifier used by applications (doesn't change on rotation)
 * - keyId: Unique identifier for this specific key version (UUID)
 * - version: Version number (starts at 1, increments on rotation)
 * - currentVersion: True for the active version, false for historical versions
 */
@Entity
@Table(name = "encryption_keys", indexes = {
    @Index(name = "idx_logical_key_version", columnList = "logical_key_id, version"),
    @Index(name = "idx_logical_key_current", columnList = "logical_key_id, current_version"),
    @Index(name = "idx_active", columnList = "active")
})
public class KeyEntity {

    @Id
    @Column(name = "key_id", nullable = false, length = 36)
    private String keyId;

    @Column(name = "logical_key_id", nullable = false, length = 36)
    private String logicalKeyId;

    @Column(name = "version", nullable = false)
    private Integer version;

    @Column(name = "current_version", nullable = false)
    private Boolean currentVersion = true;

    @Column(name = "key_material", nullable = false, columnDefinition = "BYTEA")
    private byte[] keyMaterial;

    @Column(name = "algorithm", nullable = false, length = 50)
    private String algorithm;

    @Column(name = "key_size", nullable = false)
    private Integer keySize;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "active", nullable = false)
    private Boolean active = true;

    @Column(name = "rotated_at")
    private LocalDateTime rotatedAt;

    @Column(name = "rotation_reason", length = 500)
    private String rotationReason;

    // Constructors
    public KeyEntity() {
    }

    public KeyEntity(String keyId, byte[] keyMaterial, String algorithm, Integer keySize) {
        this.keyId = keyId;
        this.logicalKeyId = keyId; // For backward compatibility, default to same as keyId
        this.version = 1;
        this.currentVersion = true;
        this.keyMaterial = keyMaterial;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.active = true;
    }

    public KeyEntity(String keyId, String logicalKeyId, Integer version, byte[] keyMaterial, 
                    String algorithm, Integer keySize) {
        this.keyId = keyId;
        this.logicalKeyId = logicalKeyId;
        this.version = version;
        this.currentVersion = true;
        this.keyMaterial = keyMaterial;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.active = true;
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

    public byte[] getKeyMaterial() {
        return keyMaterial;
    }

    public void setKeyMaterial(byte[] keyMaterial) {
        this.keyMaterial = keyMaterial;
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
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
}
