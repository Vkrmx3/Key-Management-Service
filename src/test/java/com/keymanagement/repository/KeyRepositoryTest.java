package com.keymanagement.repository;

import com.keymanagement.entity.KeyEntity;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.test.context.TestPropertySource;

import java.sql.DriverManager;
import java.util.Optional;
import java.util.UUID;

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

    @Autowired
    private EntityManager entityManager;

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
        entityManager.flush(); // Flush to trigger @CreationTimestamp

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
        keyRepository.save(keyEntity);
        KeyEntity retrieved = keyRepository.findById("large-key").orElseThrow();

        // Then
        assertArrayEquals(keyMaterial, retrieved.getKeyMaterial());
        assertEquals(32, retrieved.getKeyMaterial().length);
    }

    @Test
    void testKeyEntity_CreatedAtShouldBeAutoSet() {
        // Given & When
        KeyEntity saved = keyRepository.save(testKeyEntity);
        entityManager.flush(); // Flush to trigger @CreationTimestamp

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

    @Test
    void testMaxVersion_IncludesInactiveHistory() {
        KeyEntity current = new KeyEntity("current", "logical-key", 1, new byte[32], "AES", 256);
        KeyEntity retired = new KeyEntity("retired", "logical-key", 3, new byte[32], "AES", 256);
        retired.setActive(false);
        retired.setCurrentVersion(false);
        keyRepository.saveAndFlush(current);
        keyRepository.saveAndFlush(retired);

        assertEquals(3, keyRepository.findMaxVersionByLogicalKeyId("logical-key"));
    }

    @Test
    void testDuplicateLogicalVersion_IsRejected() {
        keyRepository.saveAndFlush(new KeyEntity("first", "logical-key", 1, new byte[32], "AES", 256));
        KeyEntity duplicate = new KeyEntity("duplicate", "logical-key", 1, new byte[32], "AES", 256);

        assertThrows(DataIntegrityViolationException.class, () -> keyRepository.saveAndFlush(duplicate));
    }

    @Test
    void testVersioningUpgrade_PreservesLegacyKeysAndIsIdempotent() throws Exception {
        String url = "jdbc:h2:mem:versioning-upgrade-" + UUID.randomUUID() + ";MODE=PostgreSQL";
        ClassPathResource migration = new ClassPathResource("db/upgrade-key-versioning.sql");
        try (var connection = DriverManager.getConnection(url, "sa", "")) {
            try (var statement = connection.createStatement()) {
                statement.execute("CREATE TABLE encryption_keys (key_id VARCHAR(36) PRIMARY KEY, "
                        + "key_material BYTEA NOT NULL, algorithm VARCHAR(50) NOT NULL, key_size INTEGER NOT NULL, "
                        + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, description VARCHAR(500), active BOOLEAN NOT NULL)");
            }
            byte[] originalMaterial = new byte[32];
            originalMaterial[0] = 42;
            try (var insert = connection.prepareStatement("INSERT INTO encryption_keys "
                    + "(key_id, key_material, algorithm, key_size, description, active) VALUES (?, ?, ?, ?, ?, ?)")) {
                insert.setString(1, "legacy-key");
                insert.setBytes(2, originalMaterial);
                insert.setString(3, "AES");
                insert.setInt(4, 256);
                insert.setString(5, "Existing key");
                insert.setBoolean(6, true);
                insert.executeUpdate();
            }

            ScriptUtils.executeSqlScript(connection, migration);
            try (var statement = connection.createStatement();
                 var result = statement.executeQuery("SELECT * FROM encryption_keys WHERE key_id = 'legacy-key'")) {
                assertTrue(result.next());
                assertEquals("legacy-key", result.getString("logical_key_id"));
                assertEquals(1, result.getInt("version"));
                assertTrue(result.getBoolean("current_version"));
                assertTrue(result.getBoolean("active"));
                assertArrayEquals(originalMaterial, result.getBytes("key_material"));
                assertEquals("Existing key", result.getString("description"));
            }

            try (var statement = connection.createStatement()) {
                statement.executeUpdate("UPDATE encryption_keys SET current_version = FALSE, active = FALSE WHERE key_id = 'legacy-key'");
            }
            ScriptUtils.executeSqlScript(connection, migration);
            try (var statement = connection.createStatement();
                 var result = statement.executeQuery("SELECT * FROM encryption_keys WHERE key_id = 'legacy-key'")) {
                assertTrue(result.next());
                assertFalse(result.getBoolean("current_version"));
                assertFalse(result.getBoolean("active"));
                assertEquals(1, result.getInt("version"));
                assertArrayEquals(originalMaterial, result.getBytes("key_material"));
            }
        }
    }
}
