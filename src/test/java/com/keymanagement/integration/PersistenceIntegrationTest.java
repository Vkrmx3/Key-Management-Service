package com.keymanagement.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.keymanagement.dto.CreateKeyResponse;
import com.keymanagement.dto.DecryptRequest;
import com.keymanagement.dto.DecryptResponse;
import com.keymanagement.dto.EncryptRequest;
import com.keymanagement.dto.EncryptResponse;
import com.keymanagement.dto.RotateKeyResponse;
import com.keymanagement.entity.KeyEntity;
import com.keymanagement.model.EncryptionAlgorithm;
import com.keymanagement.repository.KeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration tests for the KMS application with PostgreSQL persistence.
 * Tests the complete flow from REST API through to database storage.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "classpath:application.properties")
@ActiveProfiles("integration-test")
@Import(IntegrationTestSecurityConfig.class)
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

        @ParameterizedTest
        @EnumSource(EncryptionAlgorithm.class)
        void testRotationLifecycle_PreservesOldDataAndEncryptsWithCurrentVersion(EncryptionAlgorithm algorithm) {
        ResponseEntity<CreateKeyResponse> created = restTemplate.postForEntity(baseUrl,
            Map.of("algorithm", algorithm.name()), CreateKeyResponse.class);
        assertEquals(HttpStatus.CREATED, created.getStatusCode());
        CreateKeyResponse creation = created.getBody();
        assertNotNull(creation);
        assertEquals(algorithm.getDisplayName(), creation.getAlgorithm());
        assertEquals(algorithm.getKeySize(), creation.getKeySize());
        String logicalKeyId = creation.getKeyId();
        String plaintext = "Versioned data for " + algorithm.name();
        JsonNode originalEncrypted = encryptWithMetadata(logicalKeyId, plaintext);

        ResponseEntity<RotateKeyResponse> rotationResponse = restTemplate.postForEntity(
            baseUrl + "/" + logicalKeyId + "/rotate", Map.of("reason", "Lifecycle test"), RotateKeyResponse.class);
        assertEquals(HttpStatus.CREATED, rotationResponse.getStatusCode());
        RotateKeyResponse rotation = rotationResponse.getBody();
        assertNotNull(rotation);
        assertEquals(1, rotation.getOldVersion());
        assertEquals(2, rotation.getNewVersion());
        KeyEntity newKey = keyRepository.findById(rotation.getNewKeyId()).orElseThrow();
        assertEquals(algorithm.getAlgorithm(), newKey.getAlgorithm());
        assertEquals(algorithm.getKeySizeBytes(), newKey.getKeyMaterial().length);

        JsonNode newlyEncrypted = encryptWithMetadata(logicalKeyId, plaintext);
        assertDecryptsWith(rotation.getNewKeyId(), newlyEncrypted, plaintext);
        assertEquals(rotation.getNewKeyId(), newlyEncrypted.path("keyId").asText());
        assertDecryptsWith(logicalKeyId, originalEncrypted, plaintext);

        ResponseEntity<JsonNode> reencryptedResponse = restTemplate.postForEntity(
            baseUrl + "/" + logicalKeyId + "/reencrypt",
            Map.of("ciphertext", originalEncrypted.path("ciphertext").asText(),
                "nonce", originalEncrypted.path("nonce").asText(), "sourceVersion", 1), JsonNode.class);
        assertEquals(HttpStatus.OK, reencryptedResponse.getStatusCode());
        JsonNode reencrypted = reencryptedResponse.getBody();
        assertNotNull(reencrypted);
        assertEquals(rotation.getNewKeyId(), reencrypted.path("keyId").asText());
        assertDecryptsWith(rotation.getNewKeyId(), reencrypted, plaintext);
        assertEquals(1, keyRepository.findAll().stream().filter(KeyEntity::getCurrentVersion).count());
        }

        private JsonNode encryptWithMetadata(String keyId, String plaintext) {
        ResponseEntity<JsonNode> response = restTemplate.postForEntity(baseUrl + "/" + keyId + "/encrypt",
            new EncryptRequest(plaintext), JsonNode.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        JsonNode body = response.getBody();
        assertNotNull(body);
        return body;
        }

    @Test
    void testConcurrentRotations_KeepOneCurrentVersion() throws Exception {
        String logicalKeyId = createKey();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        Callable<ResponseEntity<RotateKeyResponse>> rotate = () -> {
            ready.countDown();
            assertTrue(start.await(10, TimeUnit.SECONDS));
            return restTemplate.postForEntity(baseUrl + "/" + logicalKeyId + "/rotate", null, RotateKeyResponse.class);
        };

        try (var executor = Executors.newFixedThreadPool(2)) {
            var firstRotation = executor.submit(rotate);
            var secondRotation = executor.submit(rotate);
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            start.countDown();
            ResponseEntity<RotateKeyResponse> first = firstRotation.get(20, TimeUnit.SECONDS);
            ResponseEntity<RotateKeyResponse> second = secondRotation.get(20, TimeUnit.SECONDS);
            assertEquals(HttpStatus.CREATED, first.getStatusCode());
            assertEquals(HttpStatus.CREATED, second.getStatusCode());
            RotateKeyResponse firstBody = first.getBody();
            RotateKeyResponse secondBody = second.getBody();
            assertNotNull(firstBody);
            assertNotNull(secondBody);
            assertEquals(List.of(2, 3), Stream.of(firstBody.getNewVersion(), secondBody.getNewVersion()).sorted().toList());
            List<KeyEntity> versions = keyRepository.findByLogicalKeyIdAndActiveTrueOrderByVersionDesc(logicalKeyId);
            assertEquals(List.of(3, 2, 1), versions.stream().map(KeyEntity::getVersion).toList());
            assertEquals(1, versions.stream().filter(KeyEntity::getCurrentVersion).count());
        }
    }

    @Test
    void testCreateKey_OversizedDescription_IsRejected() {
        ResponseEntity<String> response = restTemplate.postForEntity(baseUrl,
                Map.of("description", "x".repeat(501)), String.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(0, keyRepository.count());
    }

    @Test
    void testRotateKey_OversizedReason_IsRejected() {
        String keyId = createKey();
        ResponseEntity<String> response = restTemplate.postForEntity(baseUrl + "/" + keyId + "/rotate",
                Map.of("reason", "x".repeat(501)), String.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(1, keyRepository.count());
        assertTrue(keyRepository.findById(keyId).orElseThrow().getCurrentVersion());
    }

    @Test
    void testReEncrypt_InvalidSourceVersion_IsRejected() {
        String keyId = createKey();
        JsonNode encrypted = encryptWithMetadata(keyId, "Version validation");
        ResponseEntity<String> response = restTemplate.postForEntity(baseUrl + "/" + keyId + "/reencrypt",
                Map.of("ciphertext", encrypted.path("ciphertext").asText(),
                        "nonce", encrypted.path("nonce").asText(), "sourceVersion", 0), String.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

        private void assertDecryptsWith(String keyId, JsonNode encrypted, String plaintext) {
        ResponseEntity<DecryptResponse> response = restTemplate.postForEntity(baseUrl + "/" + keyId + "/decrypt",
            new DecryptRequest(encrypted.path("ciphertext").asText(), encrypted.path("nonce").asText()),
            DecryptResponse.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        DecryptResponse body = response.getBody();
        assertNotNull(body);
        assertEquals(plaintext, body.getPlaintext());
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
