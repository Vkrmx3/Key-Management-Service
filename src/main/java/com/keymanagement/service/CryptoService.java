package com.keymanagement.service;

import com.keymanagement.exception.DecryptionException;
import com.keymanagement.exception.EncryptionException;
import com.keymanagement.model.EncryptedData;
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

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256; // AES-256
    private static final int NONCE_SIZE = 12; // 12 bytes (96 bits) - recommended for GCM
    private static final int TAG_SIZE = 128; // 128 bits authentication tag

    private final SecureRandom secureRandom;

    public CryptoService() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a new AES-256 key.
     *
     * @return A new SecretKey
     */
    public SecretKey generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE, secureRandom);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
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

            return new EncryptedData(ciphertext, nonce);
        } catch (Exception e) {
            // Never log the plaintext or key in the error message
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
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            // Never log the ciphertext, key, or nonce in the error message
            throw new DecryptionException("Decryption operation failed", e);
        }
    }
}
