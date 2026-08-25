package com.keymanagement.integration;

import com.keymanagement.dto.CreateKeyResponse;
import com.keymanagement.dto.DecryptRequest;
import com.keymanagement.dto.DecryptResponse;
import com.keymanagement.dto.EncryptRequest;
import com.keymanagement.dto.EncryptResponse;
import com.keymanagement.entity.KeyEntity;
import com.keymanagement.repository.KeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration tests for the KMS application with PostgreSQL persistence.
 * Tests the complete flow from REST API through to database storage.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "classpath:application.properties")
class PersistenceIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private KeyRepository keyRepository;

    private String baseUrl;

    @BeforeEach
    void setUp() {
        baseUrl = "http://localhost:" + port + "/api/keys";
        keyRepository.deleteAll();
    }

    @Test
    void testFullEncryptDecryptFlow_ShouldPersistInDatabase() {
        // 1. Create a new key
        ResponseEntity<CreateKeyResponse> createResponse = restTemplate.postForEntity(
                baseUrl,
                null,
                CreateKeyResponse.class
        );

        assertEquals(HttpStatus.CREATED, createResponse.getStatusCode());
        assertNotNull(createResponse.getBody());
        String keyId = createResponse.getBody().getKeyId();
        assertNotNull(keyId);

        // Verify key is persisted in database
        KeyEntity keyEntity = keyRepository.findById(keyId).orElseThrow();
        assertEquals("AES", keyEntity.getAlgorithm());
        assertEquals(256, keyEntity.getKeySize());
        assertTrue(keyEntity.getActive());
        assertNotNull(keyEntity.getCreatedAt());

        // 2. Encrypt data
        String plaintext = "This is a secret message stored in PostgreSQL!";
        EncryptRequest encryptRequest = new EncryptRequest(plaintext);

        ResponseEntity<EncryptResponse> encryptResponse = restTemplate.postForEntity(
                baseUrl + "/" + keyId + "/encrypt",
                encryptRequest,
                EncryptResponse.class
        );

        assertEquals(HttpStatus.OK, encryptResponse.getStatusCode());
        assertNotNull(encryptResponse.getBody());
        String ciphertext = encryptResponse.getBody().getCiphertext();
        String nonce = encryptResponse.getBody().getNonce();
        assertNotNull(ciphertext);
        assertNotNull(nonce);

        // Verify key still exists and is active
        KeyEntity afterEncrypt = keyRepository.findById(keyId).orElseThrow();
        assertTrue(afterEncrypt.getActive());

        // 3. Decrypt data
        DecryptRequest decryptRequest = new DecryptRequest(ciphertext, nonce);

        ResponseEntity<DecryptResponse> decryptResponse = restTemplate.postForEntity(
                baseUrl + "/" + keyId + "/decrypt",
                decryptRequest,
                DecryptResponse.class
        );

        assertEquals(HttpStatus.OK, decryptResponse.getStatusCode());
        assertNotNull(decryptResponse.getBody());
        assertEquals(plaintext, decryptResponse.getBody().getPlaintext());
    }

    @Test
    void testMultipleKeysInDatabase() {
        // Create multiple keys
        String keyId1 = createKey();
        String keyId2 = createKey();
        String keyId3 = createKey();

        // Verify all keys are in database
        assertEquals(3, keyRepository.count());
        assertTrue(keyRepository.findById(keyId1).isPresent());
        assertTrue(keyRepository.findById(keyId2).isPresent());
        assertTrue(keyRepository.findById(keyId3).isPresent());

        // Verify all keys are active
        keyRepository.findAll().forEach(entity -> assertTrue(entity.getActive()));
    }

    @Test
    void testEncryptionWithDifferentKeys_ShouldProduceDifferentCiphertext() {
        // Create two different keys
        String keyId1 = createKey();
        String keyId2 = createKey();

        // Encrypt same plaintext with both keys
        String plaintext = "Same message";
        String ciphertext1 = encrypt(keyId1, plaintext);
        String ciphertext2 = encrypt(keyId2, plaintext);

        // Ciphertexts should be different
        assertNotEquals(ciphertext1, ciphertext2);
    }

    @Test
    void testInvalidKeyId_ShouldReturn404() {
        // Try to encrypt with non-existent key
        EncryptRequest request = new EncryptRequest("test");
        
        ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl + "/invalid-key-id/encrypt",
                request,
                String.class
        );

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    void testDatabasePersistenceAcrossMultipleOperations() {
        // Create key
        String keyId = createKey();
        
        // Perform multiple encrypt operations
        String plaintext1 = "Message 1";
        String plaintext2 = "Message 2";
        String plaintext3 = "Message 3";
        
        String ciphertext1 = encrypt(keyId, plaintext1);
        String ciphertext2 = encrypt(keyId, plaintext2);
        String ciphertext3 = encrypt(keyId, plaintext3);
        
        // Verify key is still in database and active
        KeyEntity keyEntity = keyRepository.findById(keyId).orElseThrow();
        assertTrue(keyEntity.getActive());
        assertEquals("AES", keyEntity.getAlgorithm());
        
        // Verify all ciphertexts are different (due to different nonces)
        assertNotEquals(ciphertext1, ciphertext2);
        assertNotEquals(ciphertext2, ciphertext3);
        assertNotEquals(ciphertext1, ciphertext3);
    }

    @Test
    void testKeyMetadataInDatabase() {
        // Create a key
        String keyId = createKey();
        
        // Retrieve from database and verify metadata
        KeyEntity entity = keyRepository.findById(keyId).orElseThrow();
        
        assertNotNull(entity.getKeyId());
        assertEquals("AES", entity.getAlgorithm());
        assertEquals(256, entity.getKeySize());
        assertEquals(32, entity.getKeyMaterial().length); // 256 bits = 32 bytes
        assertTrue(entity.getActive());
        assertNotNull(entity.getCreatedAt());
    }

    @Test
    void testKeyCountInDatabase() {
        // Initially empty
        assertEquals(0, keyRepository.countByActiveTrue());
        
        // Create keys
        createKey();
        createKey();
        createKey();
        
        // Verify count
        assertEquals(3, keyRepository.countByActiveTrue());
        assertEquals(3, keyRepository.count());
    }

    @Test
    void testNonceUniqueness_ShouldProduceDifferentNonces() {
        // Create key
        String keyId = createKey();
        String plaintext = "Same message";
        
        // Encrypt same message multiple times
        EncryptRequest request = new EncryptRequest(plaintext);
        
        ResponseEntity<EncryptResponse> response1 = restTemplate.postForEntity(
                baseUrl + "/" + keyId + "/encrypt",
                request,
                EncryptResponse.class
        );
        
        ResponseEntity<EncryptResponse> response2 = restTemplate.postForEntity(
                baseUrl + "/" + keyId + "/encrypt",
                request,
                EncryptResponse.class
        );
        
        // Nonces should be different
        assertNotEquals(response1.getBody().getNonce(), response2.getBody().getNonce());
        // Ciphertexts should be different
        assertNotEquals(response1.getBody().getCiphertext(), response2.getBody().getCiphertext());
    }

    // Helper methods

    private String createKey() {
        ResponseEntity<CreateKeyResponse> response = restTemplate.postForEntity(
                baseUrl,
                null,
                CreateKeyResponse.class
        );
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        return response.getBody().getKeyId();
    }

    private String encrypt(String keyId, String plaintext) {
        EncryptRequest request = new EncryptRequest(plaintext);
        ResponseEntity<EncryptResponse> response = restTemplate.postForEntity(
                baseUrl + "/" + keyId + "/encrypt",
                request,
                EncryptResponse.class
        );
        assertEquals(HttpStatus.OK, response.getStatusCode());
        return response.getBody().getCiphertext();
    }
}
