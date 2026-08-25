package com.keymanagement.service;

import com.keymanagement.dto.CreateKeyRequest;
import com.keymanagement.dto.CreateKeyResponse;
import com.keymanagement.model.EncryptedData;
import com.keymanagement.model.EncryptionAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Service that orchestrates key management operations.
 * Coordinates between CryptoService and KeyStorageService.
 */
@Service
public class KeyManagementService {

    private static final Logger log = LoggerFactory.getLogger(KeyManagementService.class);
    private final CryptoService cryptoService;
    private final KeyStorageService keyStorageService;
    private final KeyRotationService keyRotationService;

    public KeyManagementService(CryptoService cryptoService, 
                               KeyStorageService keyStorageService,
                               KeyRotationService keyRotationService) {
        this.cryptoService = cryptoService;
        this.keyStorageService = keyStorageService;
        this.keyRotationService = keyRotationService;
        log.info("KeyManagementService initialized");
    }

    /**
     * Creates a new encryption key with default algorithm (AES-256-GCM).
     *
     * @return The unique identifier for the created key
     */
    public String createKey() {
        return createKey(null);
    }

    /**
     * Creates a new encryption key with specified algorithm.
     *
     * @param request The create key request with optional algorithm
     * @return Response with key ID and algorithm info
     */
    public CreateKeyResponse createKey(CreateKeyRequest request) {
        // Parse algorithm from request, default to AES-256-GCM
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_256_GCM;
        if (request != null && request.getAlgorithm() != null) {
            algorithm = EncryptionAlgorithm.fromString(request.getAlgorithm());
        }

        log.debug("Creating new encryption key with algorithm: {}", algorithm.getDisplayName());
        SecretKey key = cryptoService.generateKey(algorithm);
        String keyId = keyStorageService.storeKey(key);
        log.debug("New {} key created and stored with ID: {}", algorithm.getDisplayName(), keyId);
        
        return new CreateKeyResponse(keyId, algorithm.getDisplayName(), algorithm.getKeySize());
    }

    /**
     * Encrypts plaintext using the specified key.
     *
     * @param keyId     The identifier of the key to use
     * @param plaintext The plaintext string to encrypt
     * @return EncryptedData containing ciphertext and nonce
     */
    public EncryptedData encryptData(String keyId, String plaintext) {
        log.debug("Encrypting data with key ID: {}", keyId);
        SecretKey key = keyStorageService.getKey(keyId);
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        EncryptedData encryptedData = cryptoService.encrypt(key, plaintextBytes);
        log.debug("Data encrypted successfully with key ID: {}", keyId);
        return encryptedData;
    }

    /**
     * Decrypts ciphertext using the specified key.
     *
     * @param keyId          The identifier of the key to use
     * @param ciphertextB64  The Base64-encoded ciphertext
     * @param nonceB64       The Base64-encoded nonce
     * @return The decrypted plaintext string
     */
    public String decryptData(String keyId, String ciphertextB64, String nonceB64) {
        log.debug("Decrypting data with key ID: {}", keyId);
        SecretKey key = keyStorageService.getKey(keyId);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
        byte[] nonce = Base64.getDecoder().decode(nonceB64);
        byte[] plaintextBytes = cryptoService.decrypt(key, ciphertext, nonce);
        log.debug("Data decrypted successfully with key ID: {}", keyId);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    /**
     * Re-encrypts data with the current version of a key.
     * If sourceVersion is not specified, uses the current version for decryption.
     *
     * @param logicalKeyId   The logical key identifier
     * @param sourceVersion  The version used to encrypt the data (optional)
     * @param ciphertextB64  The Base64-encoded ciphertext
     * @param nonceB64       The Base64-encoded nonce
     * @return New EncryptedData with current key version
     */
    public EncryptedData reEncryptData(String logicalKeyId, Integer sourceVersion, 
                                      String ciphertextB64, String nonceB64) {
        log.debug("Re-encrypting data for logical key ID: {}", logicalKeyId);
        
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
        byte[] nonce = Base64.getDecoder().decode(nonceB64);
        
        EncryptedData oldEncryptedData = new EncryptedData(ciphertext, nonce);
        
        // If no source version specified, use current version
        if (sourceVersion == null) {
            sourceVersion = keyRotationService.getCurrentVersion(logicalKeyId).getVersion();
        }
        
        EncryptedData newEncryptedData = keyRotationService.reEncryptData(
                logicalKeyId, 
                sourceVersion, 
                oldEncryptedData
        );
        
        log.debug("Data re-encrypted successfully for logical key ID: {}", logicalKeyId);
        return newEncryptedData;
    }
}
