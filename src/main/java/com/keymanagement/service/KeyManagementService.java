package com.keymanagement.service;

import com.keymanagement.model.EncryptedData;
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

    private final CryptoService cryptoService;
    private final KeyStorageService keyStorageService;

    public KeyManagementService(CryptoService cryptoService, KeyStorageService keyStorageService) {
        this.cryptoService = cryptoService;
        this.keyStorageService = keyStorageService;
    }

    /**
     * Creates a new encryption key and stores it.
     *
     * @return The unique identifier for the created key
     */
    public String createKey() {
        SecretKey key = cryptoService.generateKey();
        return keyStorageService.storeKey(key);
    }

    /**
     * Encrypts plaintext using the specified key.
     *
     * @param keyId     The identifier of the key to use
     * @param plaintext The plaintext string to encrypt
     * @return EncryptedData containing ciphertext and nonce
     */
    public EncryptedData encryptData(String keyId, String plaintext) {
        SecretKey key = keyStorageService.getKey(keyId);
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        return cryptoService.encrypt(key, plaintextBytes);
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
        SecretKey key = keyStorageService.getKey(keyId);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
        byte[] nonce = Base64.getDecoder().decode(nonceB64);
        byte[] plaintextBytes = cryptoService.decrypt(key, ciphertext, nonce);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }
}
