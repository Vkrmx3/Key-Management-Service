package com.keymanagement.service;

import com.keymanagement.exception.DecryptionException;
import com.keymanagement.exception.EncryptionException;
import com.keymanagement.model.EncryptedData;
import com.keymanagement.model.EncryptionAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Service for cryptographic operations supporting multiple algorithms.
 * Uses Java JCA/JCE for all cryptographic operations.
 * 
 * Supported algorithms:
 * - AES-128-GCM, AES-192-GCM, AES-256-GCM (Authenticated Encryption)
 * - ChaCha20-Poly1305 (Modern AEAD)
 */
@Service
public class CryptoService {

    private static final Logger log = LoggerFactory.getLogger(CryptoService.class);
    private final SecureRandom secureRandom;

    public CryptoService() {
        this.secureRandom = new SecureRandom();
        log.info("CryptoService initialized with multi-algorithm support: AES-GCM (128/192/256), ChaCha20-Poly1305");
    }

    /**
     * Generates a new key with default algorithm (AES-256-GCM).
     *
     * @return A new SecretKey
     */
    public SecretKey generateKey() {
        return generateKey(EncryptionAlgorithm.AES_256_GCM);
    }

    /**
     * Generates a new key with specified algorithm.
     *
     * @param algorithm The encryption algorithm to use
     * @return A new SecretKey
     */
    public SecretKey generateKey(EncryptionAlgorithm algorithm) {
        try {
            log.debug("Generating new {} key ({} bits)", algorithm.getDisplayName(), algorithm.getKeySize());
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm.getAlgorithm());
            keyGenerator.init(algorithm.getKeySize(), secureRandom);
            SecretKey key = keyGenerator.generateKey();
            log.debug("Successfully generated new {} key", algorithm.getDisplayName());
            return key;
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to generate key: algorithm not found - {}", algorithm.getDisplayName(), e);
            throw new EncryptionException("Failed to generate key for algorithm: " + algorithm.getDisplayName(), e);
        }
    }

    /**
     * Encrypts plaintext using the specified algorithm with a fresh nonce.
     *
     * @param key       The secret key to use for encryption
     * @param plaintext The plaintext bytes to encrypt
     * @param algorithm The encryption algorithm to use
     * @return EncryptedData containing ciphertext and nonce
     */
    public EncryptedData encrypt(SecretKey key, byte[] plaintext, EncryptionAlgorithm algorithm) {
        try {
            // Generate a fresh nonce for this encryption
            byte[] nonce = new byte[algorithm.getNonceSize()];
            secureRandom.nextBytes(nonce);

            // Initialize cipher in encrypt mode
            Cipher cipher = Cipher.getInstance(algorithm.getTransformation());
            AlgorithmParameterSpec parameterSpec = createParameterSpec(algorithm, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            // Encrypt the plaintext
            byte[] ciphertext = cipher.doFinal(plaintext);

            log.debug("Encryption operation completed successfully with {}", algorithm.getDisplayName());
            return new EncryptedData(ciphertext, nonce);
        } catch (Exception e) {
            // Never log the plaintext or key in the error message
            log.error("Encryption operation failed with {}", algorithm.getDisplayName(), e);
            throw new EncryptionException("Encryption operation failed for " + algorithm.getDisplayName(), e);
        }
    }

    /**
     * Encrypts plaintext using default algorithm (AES-256-GCM).
     *
     * @param key       The secret key to use for encryption
     * @param plaintext The plaintext bytes to encrypt
     * @return EncryptedData containing ciphertext and nonce
     */
    public EncryptedData encrypt(SecretKey key, byte[] plaintext) {
        // Detect algorithm from key
        EncryptionAlgorithm algorithm = detectAlgorithmFromKey(key);
        return encrypt(key, plaintext, algorithm);
    }

    /**
     * Decrypts ciphertext using the specified algorithm.
     *
     * @param key        The secret key to use for decryption
     * @param ciphertext The ciphertext bytes to decrypt
     * @param nonce      The nonce used during encryption
     * @param algorithm  The encryption algorithm to use
     * @return The decrypted plaintext bytes
     */
    public byte[] decrypt(SecretKey key, byte[] ciphertext, byte[] nonce, EncryptionAlgorithm algorithm) {
        try {
            // Initialize cipher in decrypt mode
            Cipher cipher = Cipher.getInstance(algorithm.getTransformation());
            AlgorithmParameterSpec parameterSpec = createParameterSpec(algorithm, nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            // Decrypt the ciphertext (AEAD will verify the authentication tag)
            byte[] plaintext = cipher.doFinal(ciphertext);
            log.debug("Decryption operation completed successfully with {}", algorithm.getDisplayName());
            return plaintext;
        } catch (Exception e) {
            // Never log the ciphertext, key, or nonce in the error message
            log.error("Decryption operation failed with {} - possible tampering or incorrect key/nonce", 
                     algorithm.getDisplayName(), e);
            throw new DecryptionException("Decryption operation failed for " + algorithm.getDisplayName(), e);
        }
    }

    /**
     * Decrypts ciphertext (algorithm auto-detected from key).
     *
     * @param key        The secret key to use for decryption
     * @param ciphertext The ciphertext bytes to decrypt
     * @param nonce      The nonce used during encryption
     * @return The decrypted plaintext bytes
     */
    public byte[] decrypt(SecretKey key, byte[] ciphertext, byte[] nonce) {
        // Detect algorithm from key
        EncryptionAlgorithm algorithm = detectAlgorithmFromKey(key);
        return decrypt(key, ciphertext, nonce, algorithm);
    }

    /**
     * Create the appropriate parameter spec for the algorithm.
     */
    private AlgorithmParameterSpec createParameterSpec(EncryptionAlgorithm algorithm, byte[] nonce) {
        // GCM-based algorithms use GCMParameterSpec
        if (algorithm.getTransformation().contains("GCM")) {
            return new GCMParameterSpec(algorithm.getTagSize(), nonce);
        }
        // ChaCha20-Poly1305 uses IvParameterSpec (12-byte nonce)
        else if (algorithm == EncryptionAlgorithm.CHACHA20_POLY1305) {
            return new IvParameterSpec(nonce);
        }
        // Default to IvParameterSpec
        return new IvParameterSpec(nonce);
    }

    /**
     * Detect algorithm from key properties.
     * Uses key algorithm and size to determine the encryption algorithm.
     */
    private EncryptionAlgorithm detectAlgorithmFromKey(SecretKey key) {
        String keyAlg = key.getAlgorithm();
        int keySizeBits = key.getEncoded().length * 8;

        if ("AES".equals(keyAlg)) {
            if (keySizeBits == 128) {
                return EncryptionAlgorithm.AES_128_GCM;
            } else if (keySizeBits == 192) {
                return EncryptionAlgorithm.AES_192_GCM;
            } else if (keySizeBits == 256) {
                return EncryptionAlgorithm.AES_256_GCM;
            }
        } else if ("ChaCha20".equals(keyAlg)) {
            return EncryptionAlgorithm.CHACHA20_POLY1305;
        }

        // Default to AES-256-GCM if can't detect
        log.warn("Could not detect algorithm from key (alg={}, size={}), defaulting to AES-256-GCM", 
                keyAlg, keySizeBits);
        return EncryptionAlgorithm.AES_256_GCM;
    }
}
