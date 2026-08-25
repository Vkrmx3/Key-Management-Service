package com.keymanagement.service;

import com.keymanagement.entity.KeyEntity;
import com.keymanagement.exception.KeyNotFoundException;
import com.keymanagement.repository.KeyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.UUID;

/**
 * Service for storing and retrieving encryption keys in PostgreSQL database.
 * Keys are persisted with metadata including creation timestamp and status.
 */
@Service
public class KeyStorageService {

    private static final Logger log = LoggerFactory.getLogger(KeyStorageService.class);
    private final KeyRepository keyRepository;

    public KeyStorageService(KeyRepository keyRepository) {
        this.keyRepository = keyRepository;
        log.info("KeyStorageService initialized with PostgreSQL database persistence");
    }

    /**
     * Stores a new key and returns its unique identifier.
     *
     * @param key The SecretKey to store
     * @return The UUID string identifier for the stored key
     */
    @Transactional
    public String storeKey(SecretKey key) {
        String keyId = UUID.randomUUID().toString();
        
        KeyEntity keyEntity = new KeyEntity(
                keyId,
                key.getEncoded(),
                key.getAlgorithm(),
                key.getEncoded().length * 8 // key size in bits
        );
        
        keyRepository.save(keyEntity);
        long totalKeys = keyRepository.countByActiveTrue();
        log.debug("Key stored with ID: {}. Total active keys in database: {}", keyId, totalKeys);
        return keyId;
    }

    /**
     * Retrieves a key by its identifier.
     * This method supports both:
     * - Exact keyId lookups (for backward compatibility and specific version access)
     * - Logical key ID lookups (returns current version)
     *
     * @param keyId The UUID string identifier (can be physical keyId or logical key ID)
     * @return The SecretKey associated with the keyId
     * @throws KeyNotFoundException if the key does not exist
     */
    @Transactional(readOnly = true)
    public SecretKey getKey(String keyId) {
        log.debug("Retrieving key with ID: {}", keyId);
        
        // Try exact keyId match first (for backward compatibility and specific versions)
        KeyEntity keyEntity = keyRepository.findByKeyIdAndActiveTrue(keyId)
                .orElseGet(() -> {
                    // If not found by keyId, try as logical key ID (get current version)
                    return keyRepository.findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(keyId)
                            .orElseThrow(() -> {
                                log.warn("Key not found or inactive: {}", keyId);
                                return new KeyNotFoundException(keyId);
                            });
                });
        
        return new SecretKeySpec(keyEntity.getKeyMaterial(), keyEntity.getAlgorithm());
    }

    /**
     * Checks if a key exists in storage.
     * Supports both exact keyId and logical key ID lookups.
     *
     * @param keyId The UUID string identifier (can be physical keyId or logical key ID)
     * @return true if the key exists and is active, false otherwise
     */
    @Transactional(readOnly = true)
    public boolean keyExists(String keyId) {
        // Check by exact keyId first
        if (keyRepository.findByKeyIdAndActiveTrue(keyId).isPresent()) {
            return true;
        }
        // Check by logical key ID
        return keyRepository.existsByLogicalKeyIdAndActiveTrue(keyId);
    }

    /**
     * Removes a key from storage (soft delete - marks as inactive).
     *
     * @param keyId The UUID string identifier of the key to remove
     * @return true if the key was removed, false if it didn't exist
     */
    @Transactional
    public boolean removeKey(String keyId) {
        return keyRepository.findByKeyIdAndActiveTrue(keyId)
                .map(keyEntity -> {
                    keyEntity.setActive(false);
                    keyRepository.save(keyEntity);
                    log.debug("Key marked as inactive: {}", keyId);
                    return true;
                })
                .orElseGet(() -> {
                    log.debug("Attempted to remove non-existent or already inactive key: {}", keyId);
                    return false;
                });
    }

    /**
     * Returns the number of active keys currently stored.
     *
     * @return The count of active stored keys
     */
    @Transactional(readOnly = true)
    public int getKeyCount() {
        return (int) keyRepository.countByActiveTrue();
    }

    /**
     * Clears all keys from storage (marks all as inactive).
     * Primarily useful for testing.
     */
    @Transactional
    public void clearAll() {
        long count = keyRepository.countByActiveTrue();
        keyRepository.findAll().forEach(keyEntity -> {
            keyEntity.setActive(false);
            keyRepository.save(keyEntity);
        });
        log.info("Marked all keys as inactive. {} keys deactivated", count);
    }

    /**
     * Reconstructs a SecretKey from raw key material and algorithm.
     * Used for key rotation and re-encryption scenarios.
     *
     * @param keyMaterial The raw key bytes
     * @param algorithm The algorithm name (e.g., "AES")
     * @return Reconstructed SecretKey
     */
    public SecretKey reconstructSecretKey(byte[] keyMaterial, String algorithm) {
        return new SecretKeySpec(keyMaterial, algorithm);
    }
}
