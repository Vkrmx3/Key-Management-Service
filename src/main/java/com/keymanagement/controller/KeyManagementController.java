package com.keymanagement.controller;

import com.keymanagement.dto.*;
import com.keymanagement.model.EncryptedData;
import com.keymanagement.service.KeyManagementService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

/**
 * REST Controller for Key Management Service endpoints.
 * Provides APIs for key creation, encryption, and decryption.
 */
@RestController
@RequestMapping("/api/keys")
public class KeyManagementController {

    private static final Logger log = LoggerFactory.getLogger(KeyManagementController.class);
    private final KeyManagementService keyManagementService;

    public KeyManagementController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
        log.info("KeyManagementController initialized");
    }

    /**
     * Creates a new encryption key.
     *
     * @param request The create key request (can be empty)
     * @return Response containing the new key ID
     */
    @PostMapping
    public ResponseEntity<CreateKeyResponse> createKey(@RequestBody(required = false) CreateKeyRequest request) {
        log.info("Received request to create new encryption key");
        String keyId = keyManagementService.createKey();
        log.info("Successfully created new key with ID: {}", keyId);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new CreateKeyResponse(keyId));
    }

    /**
     * Encrypts plaintext using the specified key.
     *
     * @param keyId   The ID of the key to use for encryption
     * @param request The encryption request containing plaintext
     * @return Response containing the ciphertext and nonce
     */
    @PostMapping("/{keyId}/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(
            @PathVariable String keyId,
            @Valid @RequestBody EncryptRequest request) {
        
        log.info("Received encryption request for key ID: {}", keyId);
        EncryptedData encryptedData = keyManagementService.encryptData(keyId, request.getPlaintext());
        
        // Encode ciphertext and nonce to Base64 for JSON transport
        String ciphertextB64 = Base64.getEncoder().encodeToString(encryptedData.getCiphertext());
        String nonceB64 = Base64.getEncoder().encodeToString(encryptedData.getNonce());
        
        log.info("Successfully encrypted data for key ID: {}", keyId);
        return ResponseEntity.ok(new EncryptResponse(ciphertextB64, nonceB64));
    }

    /**
     * Decrypts ciphertext using the specified key.
     *
     * @param keyId   The ID of the key to use for decryption
     * @param request The decryption request containing ciphertext and nonce
     * @return Response containing the decrypted plaintext
     */
    @PostMapping("/{keyId}/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(
            @PathVariable String keyId,
            @Valid @RequestBody DecryptRequest request) {
        
        log.info("Received decryption request for key ID: {}", keyId);
        String plaintext = keyManagementService.decryptData(
                keyId, 
                request.getCiphertext(), 
                request.getNonce()
        );
        
        log.info("Successfully decrypted data for key ID: {}", keyId);
        return ResponseEntity.ok(new DecryptResponse(plaintext));
    }
}
