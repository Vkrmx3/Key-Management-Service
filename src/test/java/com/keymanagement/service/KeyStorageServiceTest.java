package com.keymanagement.service;

import com.keymanagement.entity.KeyEntity;
import com.keymanagement.exception.KeyNotFoundException;
import com.keymanagement.repository.KeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for KeyStorageService with database persistence.
 * Uses H2 in-memory database for testing (configured in test application.properties).
 */
@SpringBootTest
@TestPropertySource(locations = "classpath:application.properties")
@Transactional
class KeyStorageServiceTest {

    @Autowired
    private KeyStorageService keyStorageService;

    @Autowired
    private KeyRepository keyRepository;

    @BeforeEach
    void setUp() {
        // Clean database before each test
        keyRepository.deleteAll();
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

    // Database Persistence Tests

    @Test
    void testStoreKey_ShouldPersistInDatabase() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();

        // When
        String keyId = keyStorageService.storeKey(key);

        // Then - Verify in database
        KeyEntity entity = keyRepository.findById(keyId).orElseThrow();
        assertNotNull(entity);
        assertEquals(keyId, entity.getKeyId());
        assertEquals("AES", entity.getAlgorithm());
        assertEquals(256, entity.getKeySize());
        assertTrue(entity.getActive());
        assertNotNull(entity.getCreatedAt());
        assertArrayEquals(key.getEncoded(), entity.getKeyMaterial());
    }

    @Test
    void testGetKey_ShouldReconstructSecretKeyFromDatabase() throws NoSuchAlgorithmException {
        // Given
        SecretKey originalKey = generateTestKey();
        String keyId = keyStorageService.storeKey(originalKey);

        // When
        SecretKey retrievedKey = keyStorageService.getKey(keyId);

        // Then
        assertNotNull(retrievedKey);
        assertEquals("AES", retrievedKey.getAlgorithm());
        assertArrayEquals(originalKey.getEncoded(), retrievedKey.getEncoded());
    }

    @Test
    void testRemoveKey_ShouldSoftDeleteInDatabase() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();
        String keyId = keyStorageService.storeKey(key);
        
        // Verify key is active in database
        KeyEntity beforeRemoval = keyRepository.findById(keyId).orElseThrow();
        assertTrue(beforeRemoval.getActive());

        // When
        boolean removed = keyStorageService.removeKey(keyId);

        // Then
        assertTrue(removed);
        
        // Verify key still exists in database but is inactive
        KeyEntity afterRemoval = keyRepository.findById(keyId).orElseThrow();
        assertFalse(afterRemoval.getActive());
        
        // Verify key cannot be retrieved through service (only active keys)
        assertThrows(KeyNotFoundException.class, () -> keyStorageService.getKey(keyId));
    }

    @Test
    void testGetKey_WithInactiveKey_ShouldThrowException() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();
        String keyId = keyStorageService.storeKey(key);
        
        // Manually deactivate the key in database
        KeyEntity entity = keyRepository.findById(keyId).orElseThrow();
        entity.setActive(false);
        keyRepository.save(entity);

        // When & Then
        assertThrows(KeyNotFoundException.class, () -> keyStorageService.getKey(keyId));
    }

    @Test
    void testKeyExists_WithInactiveKey_ShouldReturnFalse() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();
        String keyId = keyStorageService.storeKey(key);
        keyStorageService.removeKey(keyId);

        // When
        boolean exists = keyStorageService.keyExists(keyId);

        // Then
        assertFalse(exists);
    }

    @Test
    void testGetKeyCount_ShouldOnlyCountActiveKeys() throws NoSuchAlgorithmException {
        // Given
        String keyId1 = keyStorageService.storeKey(generateTestKey());
        String keyId2 = keyStorageService.storeKey(generateTestKey());
        String keyId3 = keyStorageService.storeKey(generateTestKey());
        
        // Deactivate one key
        keyStorageService.removeKey(keyId2);

        // When
        int count = keyStorageService.getKeyCount();

        // Then
        assertEquals(2, count);
        
        // Verify total keys in database (including inactive)
        assertEquals(3, keyRepository.findAll().size());
    }

    @Test
    void testClearAll_ShouldDeactivateAllKeys() throws NoSuchAlgorithmException {
        // Given
        String keyId1 = keyStorageService.storeKey(generateTestKey());
        String keyId2 = keyStorageService.storeKey(generateTestKey());
        String keyId3 = keyStorageService.storeKey(generateTestKey());

        // When
        keyStorageService.clearAll();

        // Then
        assertEquals(0, keyStorageService.getKeyCount());
        
        // Verify keys still exist in database but are all inactive
        assertEquals(3, keyRepository.findAll().size());
        keyRepository.findAll().forEach(entity -> assertFalse(entity.getActive()));
    }

    @Test
    void testStoreKey_ShouldStoreCorrectKeyMaterial() throws NoSuchAlgorithmException {
        // Given
        SecretKey key = generateTestKey();
        byte[] originalKeyMaterial = key.getEncoded();

        // When
        String keyId = keyStorageService.storeKey(key);

        // Then
        KeyEntity entity = keyRepository.findById(keyId).orElseThrow();
        assertArrayEquals(originalKeyMaterial, entity.getKeyMaterial());
        assertEquals(32, entity.getKeyMaterial().length); // 256 bits = 32 bytes
    }

    @Test
    void testMultipleConcurrentOperations_ShouldMaintainConsistency() throws NoSuchAlgorithmException {
        // Given
        SecretKey key1 = generateTestKey();
        SecretKey key2 = generateTestKey();

        // When - Simulate concurrent operations
        String keyId1 = keyStorageService.storeKey(key1);
        String keyId2 = keyStorageService.storeKey(key2);
        
        SecretKey retrieved1 = keyStorageService.getKey(keyId1);
        boolean removed1 = keyStorageService.removeKey(keyId1);
        
        SecretKey retrieved2 = keyStorageService.getKey(keyId2);
        int count = keyStorageService.getKeyCount();

        // Then
        assertEquals(key1, retrieved1);
        assertTrue(removed1);
        assertEquals(key2, retrieved2);
        assertEquals(1, count); // Only key2 is active
    }

    // Helper method to generate a test AES key
    private SecretKey generateTestKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}

