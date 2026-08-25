package com.keymanagement.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * JPA Entity for storing encryption keys in the database.
 * The actual key material is stored as a byte array.
 */
@Entity
@Table(name = "encryption_keys")
public class KeyEntity {

    @Id
    @Column(name = "key_id", nullable = false, length = 36)
    private String keyId;

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

    // Constructors
    public KeyEntity() {
    }

    public KeyEntity(String keyId, byte[] keyMaterial, String algorithm, Integer keySize) {
        this.keyId = keyId;
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
}
