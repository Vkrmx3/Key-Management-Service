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
     *
     * @param keyId The UUID string identifier of the key
     * @return The SecretKey associated with the keyId
     * @throws KeyNotFoundException if the key does not exist
     */
    @Transactional(readOnly = true)
    public SecretKey getKey(String keyId) {
        log.debug("Retrieving key with ID: {}", keyId);
        KeyEntity keyEntity = keyRepository.findByKeyIdAndActiveTrue(keyId)
                .orElseThrow(() -> {
                    log.warn("Key not found or inactive: {}", keyId);
                    return new KeyNotFoundException(keyId);
                });
        
        return new SecretKeySpec(keyEntity.getKeyMaterial(), keyEntity.getAlgorithm());
    }

    /**
     * Checks if a key exists in storage.
     *
     * @param keyId The UUID string identifier of the key
     * @return true if the key exists and is active, false otherwise
     */
    @Transactional(readOnly = true)
    public boolean keyExists(String keyId) {
        return keyRepository.findByKeyIdAndActiveTrue(keyId).isPresent();
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
}
