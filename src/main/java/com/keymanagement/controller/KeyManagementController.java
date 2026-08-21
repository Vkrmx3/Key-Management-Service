package com.keymanagement.controller;

import com.keymanagement.dto.*;
import com.keymanagement.model.EncryptedData;
import com.keymanagement.service.KeyManagementService;
import jakarta.validation.Valid;
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

    private final KeyManagementService keyManagementService;

    public KeyManagementController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    /**
     * Creates a new encryption key.
     *
     * @param request The create key request (can be empty)
     * @return Response containing the new key ID
     */
    @PostMapping
    public ResponseEntity<CreateKeyResponse> createKey(@RequestBody(required = false) CreateKeyRequest request) {
        String keyId = keyManagementService.createKey();
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
        
        EncryptedData encryptedData = keyManagementService.encryptData(keyId, request.getPlaintext());
        
        // Encode ciphertext and nonce to Base64 for JSON transport
        String ciphertextB64 = Base64.getEncoder().encodeToString(encryptedData.getCiphertext());
        String nonceB64 = Base64.getEncoder().encodeToString(encryptedData.getNonce());
        
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
        
        String plaintext = keyManagementService.decryptData(
                keyId, 
                request.getCiphertext(), 
                request.getNonce()
        );
        
        return ResponseEntity.ok(new DecryptResponse(plaintext));
    }
}
