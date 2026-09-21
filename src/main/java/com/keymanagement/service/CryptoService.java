package com.keymanagement.service;

import com.keymanagement.exception.DecryptionException;
import com.keymanagement.exception.EncryptionException;
import com.keymanagement.model.EncryptedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Service for cryptographic operations using AES-256-GCM.
 * Uses Java JCA/JCE for all cryptographic operations.
 */
@Service
public class CryptoService {

    private static final Logger log = LoggerFactory.getLogger(CryptoService.class);
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256; // AES-256
    private static final int NONCE_SIZE = 12; // 12 bytes (96 bits) - recommended for GCM
    private static final int TAG_SIZE = 128; // 128 bits authentication tag

    private final SecureRandom secureRandom;

    public CryptoService() {
        this.secureRandom = new SecureRandom();
        log.info("CryptoService initialized with AES-256-GCM (key size: {} bits, nonce size: {} bytes, tag size: {} bits)", 
                KEY_SIZE, NONCE_SIZE, TAG_SIZE);
    }

    /**
     * Generates a new AES-256 key.
     *
     * @return A new SecretKey
     */
    public SecretKey generateKey() {
        try {
            log.debug("Generating new AES-{} key", KEY_SIZE);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE, secureRandom);
            SecretKey key = keyGenerator.generateKey();
            log.debug("Successfully generated new AES-{} key", KEY_SIZE);
            return key;
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to generate key: algorithm not found", e);
            throw new EncryptionException("Failed to generate key", e);
        }
    }

    /**
     * Encrypts plaintext using AES-256-GCM with a fresh nonce.
     *
     * @param key       The secret key to use for encryption
     * @param plaintext The plaintext bytes to encrypt
     * @return EncryptedData containing ciphertext and nonce
     */
    public EncryptedData encrypt(SecretKey key, byte[] plaintext) {
        try {
            // Generate a fresh 12-byte nonce for this encryption
            byte[] nonce = new byte[NONCE_SIZE];
            secureRandom.nextBytes(nonce);

            // Initialize cipher in encrypt mode
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            // Encrypt the plaintext
            byte[] ciphertext = cipher.doFinal(plaintext);

            log.debug("Encryption operation completed successfully");
            return new EncryptedData(ciphertext, nonce);
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Never log the plaintext or key in the error message
            log.error("Encryption operation failed - invalid state or arguments", e);
            throw new EncryptionException("Encryption operation failed", e);
        } catch (Exception e) {
            // Catch remaining crypto exceptions (InvalidKeyException, etc.)
            log.error("Encryption operation failed", e);
            throw new EncryptionException("Encryption operation failed", e);
        }
    }

    /**
     * Decrypts ciphertext using AES-256-GCM.
     *
     * @param key        The secret key to use for decryption
     * @param ciphertext The ciphertext bytes to decrypt
     * @param nonce      The nonce used during encryption
     * @return The decrypted plaintext bytes
     */
    public byte[] decrypt(SecretKey key, byte[] ciphertext, byte[] nonce) {
        try {
            // Initialize cipher in decrypt mode
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            // Decrypt the ciphertext (GCM will verify the authentication tag)
            byte[] plaintext = cipher.doFinal(ciphertext);
            log.debug("Decryption operation completed successfully");
            return plaintext;
        } catch (javax.crypto.AEADBadTagException e) {
            // Authentication tag verification failed - possible tampering
            log.error("Decryption operation failed - authentication tag mismatch (possible tampering)", e);
            throw new DecryptionException("Decryption failed - data may have been tampered with", e);
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Invalid state or arguments
            log.error("Decryption operation failed - invalid state or arguments", e);
            throw new DecryptionException("Decryption operation failed", e);
        } catch (Exception e) {
            // Catch remaining crypto exceptions (InvalidKeyException, etc.)
            log.error("Decryption operation failed - possible tampering or incorrect key/nonce", e);
            throw new DecryptionException("Decryption operation failed", e);
        }
    }
}
