package com.keymanagement.integration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import com.keymanagement.dto.CreateKeyResponse;
import com.keymanagement.dto.DecryptRequest;
import com.keymanagement.dto.DecryptResponse;
import com.keymanagement.dto.EncryptRequest;
import com.keymanagement.dto.EncryptResponse;
import com.keymanagement.entity.KeyEntity;
import com.keymanagement.repository.KeyRepository;

/**
 * End-to-end integration tests for KMS application with database persistence.
 * Tests the full stack: REST API -> Services -> Database
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "classpath:application.properties")
@Import(IntegrationTestSecurityConfig.class)
class KmsPersistenceIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private KeyRepository keyRepository;

    @BeforeEach
    void setUp() {
        // Clean database before each test
        keyRepository.deleteAll();
    }

    @Test
    void testFullWorkflow_CreateEncryptDecrypt_WithDatabasePersistence() {
        // Step 1: Create Key
        ResponseEntity<CreateKeyResponse> createResponse = restTemplate.postForEntity(
                "/api/keys",
                null,
                CreateKeyResponse.class
        );

        assertEquals(HttpStatus.CREATED, createResponse.getStatusCode());
        assertNotNull(createResponse.getBody());
        String keyId = createResponse.getBody().getKeyId();
        assertNotNull(keyId);

        // Verify key is in database
        KeyEntity storedKey = keyRepository.findById(keyId).orElseThrow();
        assertNotNull(storedKey);
        assertEquals("AES", storedKey.getAlgorithm());
        assertEquals(256, storedKey.getKeySize());
        assertTrue(storedKey.getActive());
        assertNotNull(storedKey.getCreatedAt());

        // Step 2: Encrypt Data
        EncryptRequest encryptRequest = new EncryptRequest("Secret Message for Integration Test");
        ResponseEntity<EncryptResponse> encryptResponse = restTemplate.postForEntity(
                "/api/keys/" + keyId + "/encrypt",
                encryptRequest,
                EncryptResponse.class
        );

        assertEquals(HttpStatus.OK, encryptResponse.getStatusCode());
        assertNotNull(encryptResponse.getBody());
        String ciphertext = encryptResponse.getBody().getCiphertext();
        String nonce = encryptResponse.getBody().getNonce();
        assertNotNull(ciphertext);
        assertNotNull(nonce);

        // Step 3: Decrypt Data
        DecryptRequest decryptRequest = new DecryptRequest(ciphertext, nonce);
        ResponseEntity<DecryptResponse> decryptResponse = restTemplate.postForEntity(
                "/api/keys/" + keyId + "/decrypt",
                decryptRequest,
                DecryptResponse.class
        );

        assertEquals(HttpStatus.OK, decryptResponse.getStatusCode());
        assertNotNull(decryptResponse.getBody());
        assertEquals("Secret Message for Integration Test", decryptResponse.getBody().getPlaintext());

        // Verify key still exists in database
        assertTrue(keyRepository.findById(keyId).isPresent());
    }

    @Test
    void testMultipleKeys_ShouldPersistIndependently() {
        // Create multiple keys
        ResponseEntity<CreateKeyResponse> response1 = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);
        ResponseEntity<CreateKeyResponse> response2 = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);
        ResponseEntity<CreateKeyResponse> response3 = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);

        String keyId1 = response1.getBody().getKeyId();
        String keyId2 = response2.getBody().getKeyId();
        String keyId3 = response3.getBody().getKeyId();

        // Verify all keys are different
        assertNotEquals(keyId1, keyId2);
        assertNotEquals(keyId2, keyId3);
        assertNotEquals(keyId1, keyId3);

        // Verify all keys exist in database
        assertEquals(3, keyRepository.countByActiveTrue());
        assertTrue(keyRepository.findByKeyIdAndActiveTrue(keyId1).isPresent());
        assertTrue(keyRepository.findByKeyIdAndActiveTrue(keyId2).isPresent());
        assertTrue(keyRepository.findByKeyIdAndActiveTrue(keyId3).isPresent());

        // Test encryption with each key
        EncryptRequest request1 = new EncryptRequest("Message 1");
        EncryptRequest request2 = new EncryptRequest("Message 2");
        EncryptRequest request3 = new EncryptRequest("Message 3");

        ResponseEntity<EncryptResponse> enc1 = restTemplate.postForEntity("/api/keys/" + keyId1 + "/encrypt", request1, EncryptResponse.class);
        ResponseEntity<EncryptResponse> enc2 = restTemplate.postForEntity("/api/keys/" + keyId2 + "/encrypt", request2, EncryptResponse.class);
        ResponseEntity<EncryptResponse> enc3 = restTemplate.postForEntity("/api/keys/" + keyId3 + "/encrypt", request3, EncryptResponse.class);

        // Verify all encryptions succeeded
        assertEquals(HttpStatus.OK, enc1.getStatusCode());
        assertEquals(HttpStatus.OK, enc2.getStatusCode());
        assertEquals(HttpStatus.OK, enc3.getStatusCode());

        // Decrypt and verify
        DecryptRequest dec1 = new DecryptRequest(enc1.getBody().getCiphertext(), enc1.getBody().getNonce());
        ResponseEntity<DecryptResponse> decResponse1 = restTemplate.postForEntity("/api/keys/" + keyId1 + "/decrypt", dec1, DecryptResponse.class);
        assertEquals("Message 1", decResponse1.getBody().getPlaintext());
    }

    @Test
    void testKeyPersistence_AfterMultipleOperations() {
        // Create key
        ResponseEntity<CreateKeyResponse> createResponse = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);
        String keyId = createResponse.getBody().getKeyId();

        // Perform multiple encrypt/decrypt operations
        for (int i = 0; i < 5; i++) {
            EncryptRequest encryptRequest = new EncryptRequest("Message " + i);
            ResponseEntity<EncryptResponse> encryptResponse = restTemplate.postForEntity(
                    "/api/keys/" + keyId + "/encrypt",
                    encryptRequest,
                    EncryptResponse.class
            );

            DecryptRequest decryptRequest = new DecryptRequest(
                    encryptResponse.getBody().getCiphertext(),
                    encryptResponse.getBody().getNonce()
            );
            ResponseEntity<DecryptResponse> decryptResponse = restTemplate.postForEntity(
                    "/api/keys/" + keyId + "/decrypt",
                    decryptRequest,
                    DecryptResponse.class
            );

            assertEquals("Message " + i, decryptResponse.getBody().getPlaintext());
        }

        // Verify key still exists and is active in database
        KeyEntity keyEntity = keyRepository.findByKeyIdAndActiveTrue(keyId).orElseThrow();
        assertTrue(keyEntity.getActive());
        assertNotNull(keyEntity.getCreatedAt());
    }

    @Test
    void testEncryptionWithNonExistentKey_ShouldReturn404() {
        // Given
        String nonExistentKeyId = "non-existent-key-12345";
        EncryptRequest request = new EncryptRequest("Test Message");

        // When
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/keys/" + nonExistentKeyId + "/encrypt",
                request,
                String.class
        );

        // Then
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    void testDecryptionWithNonExistentKey_ShouldReturn404() {
        // Given
        String nonExistentKeyId = "non-existent-key-12345";
        DecryptRequest request = new DecryptRequest("someciphertext", "somenonce");

        // When
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/keys/" + nonExistentKeyId + "/decrypt",
                request,
                String.class
        );

        // Then
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    void testDatabaseConstraints_UniqueKeyIds() {
        // Create keys and verify uniqueness
        ResponseEntity<CreateKeyResponse> response1 = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);
        ResponseEntity<CreateKeyResponse> response2 = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);

        String keyId1 = response1.getBody().getKeyId();
        String keyId2 = response2.getBody().getKeyId();

        // Verify different UUIDs generated
        assertNotEquals(keyId1, keyId2);

        // Verify both keys exist independently in database
        KeyEntity entity1 = keyRepository.findById(keyId1).orElseThrow();
        KeyEntity entity2 = keyRepository.findById(keyId2).orElseThrow();

        assertNotNull(entity1);
        assertNotNull(entity2);
        assertArrayEquals(entity1.getKeyMaterial(), keyRepository.findById(keyId1).get().getKeyMaterial());
    }

    @Test
    void testKeyMetadata_ShouldBeTracked() {
        // Create key
        ResponseEntity<CreateKeyResponse> response = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);
        String keyId = response.getBody().getKeyId();

        // Retrieve from database and verify metadata
        KeyEntity entity = keyRepository.findById(keyId).orElseThrow();
        
        assertNotNull(entity.getKeyId());
        assertNotNull(entity.getKeyMaterial());
        assertNotNull(entity.getAlgorithm());
        assertNotNull(entity.getKeySize());
        assertNotNull(entity.getCreatedAt());
        assertNotNull(entity.getActive());
        
        assertEquals("AES", entity.getAlgorithm());
        assertEquals(256, entity.getKeySize());
        assertTrue(entity.getActive());
        assertEquals(32, entity.getKeyMaterial().length); // 256 bits = 32 bytes
    }

    @Test
    void testTransactionIsolation_ConcurrentKeyCreation() throws InterruptedException {
        // Create multiple keys concurrently
        Thread[] threads = new Thread[5];
        String[] keyIds = new String[5];

        for (int i = 0; i < 5; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                ResponseEntity<CreateKeyResponse> response = restTemplate.postForEntity(
                        "/api/keys",
                        null,
                        CreateKeyResponse.class
                );
                keyIds[index] = response.getBody().getKeyId();
            });
            threads[i].start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify all keys were created successfully
        for (String keyId : keyIds) {
            assertNotNull(keyId);
            assertTrue(keyRepository.findById(keyId).isPresent());
        }

        // Verify all keys are unique
        assertEquals(5, keyRepository.countByActiveTrue());
    }

    @Test
    void testLargeDataEncryptionDecryption_WithPersistence() {
        // Create key
        ResponseEntity<CreateKeyResponse> createResponse = restTemplate.postForEntity("/api/keys", null, CreateKeyResponse.class);
        String keyId = createResponse.getBody().getKeyId();

        // Create large plaintext (1KB)
        StringBuilder largeText = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            largeText.append("This is a test message for large data encryption. ");
        }
        String plaintext = largeText.toString();

        // Encrypt
        EncryptRequest encryptRequest = new EncryptRequest(plaintext);
        ResponseEntity<EncryptResponse> encryptResponse = restTemplate.postForEntity(
                "/api/keys/" + keyId + "/encrypt",
                encryptRequest,
                EncryptResponse.class
        );

        assertEquals(HttpStatus.OK, encryptResponse.getStatusCode());

        // Decrypt
        DecryptRequest decryptRequest = new DecryptRequest(
                encryptResponse.getBody().getCiphertext(),
                encryptResponse.getBody().getNonce()
        );
        ResponseEntity<DecryptResponse> decryptResponse = restTemplate.postForEntity(
                "/api/keys/" + keyId + "/decrypt",
                decryptRequest,
                DecryptResponse.class
        );

        assertEquals(HttpStatus.OK, decryptResponse.getStatusCode());
        assertEquals(plaintext, decryptResponse.getBody().getPlaintext());

        // Verify key still exists in database
        assertTrue(keyRepository.findById(keyId).isPresent());
    }
}
