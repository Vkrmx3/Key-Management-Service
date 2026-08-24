package com.keymanagement.service;

import com.keymanagement.model.EncryptedData;
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

    public KeyManagementService(CryptoService cryptoService, KeyStorageService keyStorageService) {
        this.cryptoService = cryptoService;
        this.keyStorageService = keyStorageService;
        log.info("KeyManagementService initialized");
    }

    /**
     * Creates a new encryption key and stores it.
     *
     * @return The unique identifier for the created key
     */
    public String createKey() {
        log.debug("Creating new encryption key");
        SecretKey key = cryptoService.generateKey();
        String keyId = keyStorageService.storeKey(key);
        log.debug("New key created and stored with ID: {}", keyId);
        return keyId;
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
}
