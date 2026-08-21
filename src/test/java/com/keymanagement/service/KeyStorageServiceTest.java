package com.keymanagement.service;

import com.keymanagement.exception.KeyNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class KeyStorageServiceTest {

    private KeyStorageService keyStorageService;

    @BeforeEach
    void setUp() {
        keyStorageService = new KeyStorageService();
    }

    @Test
    void testStoreKey_ShouldReturnKeyId() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();

        // When
        String keyId = keyStorageService.storeKey(key);

        // Then
        assertNotNull(keyId);
        assertFalse(keyId.isEmpty());
    }

    @Test
    void testStoreKey_ShouldReturnUniqueKeyIds() throws NoSuchAlgorithmException {
        // Given
        SecretKey key1 = generateTestKey();
        SecretKey key2 = generateTestKey();

        // When
        String keyId1 = keyStorageService.storeKey(key1);
        String keyId2 = keyStorageService.storeKey(key2);

        // Then
        assertNotEquals(keyId1, keyId2);
    }

    @Test
    void testGetKey_WithValidKeyId_ShouldReturnKey() throws NoSuchAlgorithmException {
        // Given
        SecretKey originalKey = generateTestKey();
        String keyId = keyStorageService.storeKey(originalKey);

        // When
        SecretKey retrievedKey = keyStorageService.getKey(keyId);

        // Then
        assertNotNull(retrievedKey);
        assertEquals(originalKey, retrievedKey);
    }

    @Test
    void testGetKey_WithInvalidKeyId_ShouldThrowKeyNotFoundException() {
        // Given
        String invalidKeyId = "non-existent-key-id";

        // When & Then
        KeyNotFoundException exception = assertThrows(KeyNotFoundException.class, () -> {
            keyStorageService.getKey(invalidKeyId);
        });
        
        assertTrue(exception.getMessage().contains(invalidKeyId));
    }

    @Test
    void testKeyExists_WithValidKeyId_ShouldReturnTrue() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();
        String keyId = keyStorageService.storeKey(key);

        // When
        boolean exists = keyStorageService.keyExists(keyId);

        // Then
        assertTrue(exists);
    }

    @Test
    void testKeyExists_WithInvalidKeyId_ShouldReturnFalse() {
        // Given
        String invalidKeyId = "non-existent-key-id";

        // When
        boolean exists = keyStorageService.keyExists(invalidKeyId);

        // Then
        assertFalse(exists);
    }

    @Test
    void testRemoveKey_WithValidKeyId_ShouldReturnTrue() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();
        String keyId = keyStorageService.storeKey(key);

        // When
        boolean removed = keyStorageService.removeKey(keyId);

        // Then
        assertTrue(removed);
        assertFalse(keyStorageService.keyExists(keyId));
    }

    @Test
    void testRemoveKey_WithInvalidKeyId_ShouldReturnFalse() {
        // Given
        String invalidKeyId = "non-existent-key-id";

        // When
        boolean removed = keyStorageService.removeKey(invalidKeyId);

        // Then
        assertFalse(removed);
    }

    @Test
    void testGetKeyCount_ShouldReturnCorrectCount() throws NoSuchAlgorithmException {
        // Given - Initially empty
        assertEquals(0, keyStorageService.getKeyCount());

        // When - Store keys
        keyStorageService.storeKey(generateTestKey());
        keyStorageService.storeKey(generateTestKey());
        keyStorageService.storeKey(generateTestKey());

        // Then
        assertEquals(3, keyStorageService.getKeyCount());
    }

    @Test
    void testGetKeyCount_AfterRemoval_ShouldReturnCorrectCount() throws NoSuchAlgorithmException {
        // Given
        String keyId1 = keyStorageService.storeKey(generateTestKey());
        String keyId2 = keyStorageService.storeKey(generateTestKey());
        String keyId3 = keyStorageService.storeKey(generateTestKey());
        assertEquals(3, keyStorageService.getKeyCount());

        // When - Remove one key
        keyStorageService.removeKey(keyId2);

        // Then
        assertEquals(2, keyStorageService.getKeyCount());
        assertTrue(keyStorageService.keyExists(keyId1));
        assertFalse(keyStorageService.keyExists(keyId2));
        assertTrue(keyStorageService.keyExists(keyId3));
    }

    @Test
    void testClearAll_ShouldRemoveAllKeys() throws NoSuchAlgorithmException {
        // Given
        keyStorageService.storeKey(generateTestKey());
        keyStorageService.storeKey(generateTestKey());
        keyStorageService.storeKey(generateTestKey());
        assertEquals(3, keyStorageService.getKeyCount());

        // When
        keyStorageService.clearAll();

        // Then
        assertEquals(0, keyStorageService.getKeyCount());
    }

    @Test
    void testStoreAndRetrieveMultipleKeys() throws NoSuchAlgorithmException {
        // Given
        SecretKey key1 = generateTestKey();
        SecretKey key2 = generateTestKey();
        SecretKey key3 = generateTestKey();

        // When
        String keyId1 = keyStorageService.storeKey(key1);
        String keyId2 = keyStorageService.storeKey(key2);
        String keyId3 = keyStorageService.storeKey(key3);

        // Then
        assertEquals(key1, keyStorageService.getKey(keyId1));
        assertEquals(key2, keyStorageService.getKey(keyId2));
        assertEquals(key3, keyStorageService.getKey(keyId3));
    }

    // Helper method to generate a test AES key
    private SecretKey generateTestKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
