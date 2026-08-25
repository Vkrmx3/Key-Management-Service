package com.keymanagement.repository;

import com.keymanagement.entity.KeyEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JPA repository tests for KeyRepository.
 * Uses H2 in-memory database for testing.
 */
@DataJpaTest
@TestPropertySource(locations = "classpath:application.properties")
class KeyRepositoryTest {

    @Autowired
    private KeyRepository keyRepository;

    private KeyEntity testKeyEntity;

    @BeforeEach
    void setUp() {
        // Clean database before each test
        keyRepository.deleteAll();

        // Create test key entity
        byte[] testKeyMaterial = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        testKeyEntity = new KeyEntity("test-key-id-123", testKeyMaterial, "AES", 256);
    }

    @Test
    void testSave_ShouldPersistKeyEntity() {
        // When
        KeyEntity saved = keyRepository.save(testKeyEntity);

        // Then
        assertNotNull(saved);
        assertEquals("test-key-id-123", saved.getKeyId());
        assertEquals("AES", saved.getAlgorithm());
        assertEquals(256, saved.getKeySize());
        assertTrue(saved.getActive());
        assertNotNull(saved.getCreatedAt());
    }

    @Test
    void testFindById_WithExistingKey_ShouldReturnKey() {
        // Given
        keyRepository.save(testKeyEntity);

        // When
        Optional<KeyEntity> found = keyRepository.findById("test-key-id-123");

        // Then
        assertTrue(found.isPresent());
        assertEquals("test-key-id-123", found.get().getKeyId());
        assertArrayEquals(testKeyEntity.getKeyMaterial(), found.get().getKeyMaterial());
    }

    @Test
    void testFindById_WithNonExistingKey_ShouldReturnEmpty() {
        // When
        Optional<KeyEntity> found = keyRepository.findById("non-existent-key");

        // Then
        assertFalse(found.isPresent());
    }

    @Test
    void testFindByKeyIdAndActiveTrue_WithActiveKey_ShouldReturnKey() {
        // Given
        testKeyEntity.setActive(true);
        keyRepository.save(testKeyEntity);

        // When
        Optional<KeyEntity> found = keyRepository.findByKeyIdAndActiveTrue("test-key-id-123");

        // Then
        assertTrue(found.isPresent());
        assertTrue(found.get().getActive());
    }

    @Test
    void testFindByKeyIdAndActiveTrue_WithInactiveKey_ShouldReturnEmpty() {
        // Given
        testKeyEntity.setActive(false);
        keyRepository.save(testKeyEntity);

        // When
        Optional<KeyEntity> found = keyRepository.findByKeyIdAndActiveTrue("test-key-id-123");

        // Then
        assertFalse(found.isPresent());
    }

    @Test
    void testCountByActiveTrue_ShouldReturnCorrectCount() {
        // Given
        KeyEntity key1 = new KeyEntity("key-1", new byte[]{1, 2, 3}, "AES", 256);
        KeyEntity key2 = new KeyEntity("key-2", new byte[]{4, 5, 6}, "AES", 256);
        KeyEntity key3 = new KeyEntity("key-3", new byte[]{7, 8, 9}, "AES", 256);
        
        key1.setActive(true);
        key2.setActive(true);
        key3.setActive(false);
        
        keyRepository.save(key1);
        keyRepository.save(key2);
        keyRepository.save(key3);

        // When
        long count = keyRepository.countByActiveTrue();

        // Then
        assertEquals(2, count);
    }

    @Test
    void testUpdate_ShouldModifyKeyEntity() {
        // Given
        KeyEntity saved = keyRepository.save(testKeyEntity);
        
        // When
        saved.setDescription("Updated description");
        saved.setActive(false);
        KeyEntity updated = keyRepository.save(saved);

        // Then
        assertEquals("Updated description", updated.getDescription());
        assertFalse(updated.getActive());
    }

    @Test
    void testDelete_ShouldRemoveKeyEntity() {
        // Given
        keyRepository.save(testKeyEntity);
        assertTrue(keyRepository.existsById("test-key-id-123"));

        // When
        keyRepository.deleteById("test-key-id-123");

        // Then
        assertFalse(keyRepository.existsById("test-key-id-123"));
    }

    @Test
    void testFindAll_ShouldReturnAllKeys() {
        // Given
        KeyEntity key1 = new KeyEntity("key-1", new byte[]{1, 2, 3}, "AES", 256);
        KeyEntity key2 = new KeyEntity("key-2", new byte[]{4, 5, 6}, "AES", 256);
        
        keyRepository.save(key1);
        keyRepository.save(key2);

        // When
        var allKeys = keyRepository.findAll();

        // Then
        assertEquals(2, allKeys.size());
    }

    @Test
    void testKeyEntity_ShouldStoreKeyMaterialCorrectly() {
        // Given
        byte[] keyMaterial = new byte[32]; // 256-bit key
        for (int i = 0; i < 32; i++) {
            keyMaterial[i] = (byte) i;
        }
        KeyEntity keyEntity = new KeyEntity("large-key", keyMaterial, "AES", 256);

        // When
        KeyEntity saved = keyRepository.save(keyEntity);
        KeyEntity retrieved = keyRepository.findById("large-key").orElseThrow();

        // Then
        assertArrayEquals(keyMaterial, retrieved.getKeyMaterial());
        assertEquals(32, retrieved.getKeyMaterial().length);
    }

    @Test
    void testKeyEntity_CreatedAtShouldBeAutoSet() {
        // Given & When
        KeyEntity saved = keyRepository.save(testKeyEntity);

        // Then
        assertNotNull(saved.getCreatedAt());
    }

    @Test
    void testKeyEntity_DefaultActiveShouldBeTrue() {
        // Given
        KeyEntity keyEntity = new KeyEntity("new-key", new byte[]{1, 2, 3}, "AES", 128);
        
        // When
        KeyEntity saved = keyRepository.save(keyEntity);

        // Then
        assertTrue(saved.getActive());
    }
}
