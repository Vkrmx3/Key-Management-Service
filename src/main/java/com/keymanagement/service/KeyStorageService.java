package com.keymanagement.service;

import com.keymanagement.exception.KeyNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for storing and retrieving encryption keys in memory.
 * Uses ConcurrentHashMap for thread-safe in-memory storage.
 * Keys are identified by UUID strings.
 */
@Service
public class KeyStorageService {

    private static final Logger log = LoggerFactory.getLogger(KeyStorageService.class);
    private final ConcurrentHashMap<String, SecretKey> keyStore;

    public KeyStorageService() {
        this.keyStore = new ConcurrentHashMap<>();
        log.info("KeyStorageService initialized with in-memory storage");
    }

    /**
     * Stores a new key and returns its unique identifier.
     *
     * @param key The SecretKey to store
     * @return The UUID string identifier for the stored key
     */
    public String storeKey(SecretKey key) {
        String keyId = UUID.randomUUID().toString();
        keyStore.put(keyId, key);
        log.debug("Key stored with ID: {}. Total keys in storage: {}", keyId, keyStore.size());
        return keyId;
    }

    /**
     * Retrieves a key by its identifier.
     *
     * @param keyId The UUID string identifier of the key
     * @return The SecretKey associated with the keyId
     * @throws KeyNotFoundException if the key does not exist
     */
    public SecretKey getKey(String keyId) {
        log.debug("Retrieving key with ID: {}", keyId);
        return Optional.ofNullable(keyStore.get(keyId))
                .orElseThrow(() -> {
                    log.warn("Key not found: {}", keyId);
                    return new KeyNotFoundException(keyId);
                });
    }

    /**
     * Checks if a key exists in storage.
     *
     * @param keyId The UUID string identifier of the key
     * @return true if the key exists, false otherwise
     */
    public boolean keyExists(String keyId) {
        return keyStore.containsKey(keyId);
    }

    /**
     * Removes a key from storage.
     *
     * @param keyId The UUID string identifier of the key to remove
     * @return true if the key was removed, false if it didn't exist
     */
    public boolean removeKey(String keyId) {
        boolean removed = keyStore.remove(keyId) != null;
        if (removed) {
            log.debug("Key removed: {}. Remaining keys: {}", keyId, keyStore.size());
        } else {
            log.debug("Attempted to remove non-existent key: {}", keyId);
        }
        return removed;
    }

    /**
     * Returns the number of keys currently stored.
     *
     * @return The count of stored keys
     */
    public int getKeyCount() {
        return keyStore.size();
    }

    /**
     * Clears all keys from storage.
     * Primarily useful for testing.
     */
    public void clearAll() {
        int count = keyStore.size();
        keyStore.clear();
        log.info("Cleared all keys from storage. {} keys removed", count);
    }
}
