package com.keymanagement.service;

import com.keymanagement.model.EncryptedData;
import com.keymanagement.model.EncryptionAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for multi-algorithm support in CryptoService.
 */
class CryptoServiceMultiAlgorithmTest {

    private CryptoService cryptoService;

    @BeforeEach
    void setUp() {
        cryptoService = new CryptoService();
    }

    @Test
    void testGenerateKey_Aes128() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_128_GCM);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(16, key.getEncoded().length); // 128 bits = 16 bytes
    }

    @Test
    void testGenerateKey_Aes192() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_192_GCM);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(24, key.getEncoded().length); // 192 bits = 24 bytes
    }

    @Test
    void testGenerateKey_Aes256() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_256_GCM);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes
    }

    @Test
    void testGenerateKey_DefaultAlgorithm() {
        SecretKey key = cryptoService.generateKey();
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length); // Default is AES-256
    }

    @Test
    void testEncryptDecrypt_Aes128() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_128_GCM);
        String plaintext = "Test message with AES-128-GCM";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted = cryptoService.encrypt(key, plaintextBytes, EncryptionAlgorithm.AES_128_GCM);
        assertNotNull(encrypted);
        assertNotNull(encrypted.getCiphertext());
        assertNotNull(encrypted.getNonce());
        assertEquals(12, encrypted.getNonce().length);

        byte[] decrypted = cryptoService.decrypt(key, encrypted.getCiphertext(), 
                                                encrypted.getNonce(), EncryptionAlgorithm.AES_128_GCM);
        assertEquals(plaintext, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void testEncryptDecrypt_Aes192() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_192_GCM);
        String plaintext = "Test message with AES-192-GCM";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted = cryptoService.encrypt(key, plaintextBytes, EncryptionAlgorithm.AES_192_GCM);
        byte[] decrypted = cryptoService.decrypt(key, encrypted.getCiphertext(), 
                                                encrypted.getNonce(), EncryptionAlgorithm.AES_192_GCM);
        assertEquals(plaintext, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void testEncryptDecrypt_Aes256() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_256_GCM);
        String plaintext = "Test message with AES-256-GCM";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted = cryptoService.encrypt(key, plaintextBytes, EncryptionAlgorithm.AES_256_GCM);
        byte[] decrypted = cryptoService.decrypt(key, encrypted.getCiphertext(), 
                                                encrypted.getNonce(), EncryptionAlgorithm.AES_256_GCM);
        assertEquals(plaintext, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void testEncryptDecrypt_AutoDetect() {
        // Test auto-detection of algorithm from key
        SecretKey key128 = cryptoService.generateKey(EncryptionAlgorithm.AES_128_GCM);
        SecretKey key192 = cryptoService.generateKey(EncryptionAlgorithm.AES_192_GCM);
        SecretKey key256 = cryptoService.generateKey(EncryptionAlgorithm.AES_256_GCM);

        String plaintext = "Auto-detect test";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // Encrypt and decrypt with auto-detection
        EncryptedData encrypted128 = cryptoService.encrypt(key128, plaintextBytes);
        byte[] decrypted128 = cryptoService.decrypt(key128, encrypted128.getCiphertext(), encrypted128.getNonce());
        assertEquals(plaintext, new String(decrypted128, StandardCharsets.UTF_8));

        EncryptedData encrypted192 = cryptoService.encrypt(key192, plaintextBytes);
        byte[] decrypted192 = cryptoService.decrypt(key192, encrypted192.getCiphertext(), encrypted192.getNonce());
        assertEquals(plaintext, new String(decrypted192, StandardCharsets.UTF_8));

        EncryptedData encrypted256 = cryptoService.encrypt(key256, plaintextBytes);
        byte[] decrypted256 = cryptoService.decrypt(key256, encrypted256.getCiphertext(), encrypted256.getNonce());
        assertEquals(plaintext, new String(decrypted256, StandardCharsets.UTF_8));
    }

    @Test
    void testDifferentNoncesForSameData() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_128_GCM);
        String plaintext = "Same message";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted1 = cryptoService.encrypt(key, plaintextBytes, EncryptionAlgorithm.AES_128_GCM);
        EncryptedData encrypted2 = cryptoService.encrypt(key, plaintextBytes, EncryptionAlgorithm.AES_128_GCM);

        // Nonces should be different
        assertFalse(java.util.Arrays.equals(encrypted1.getNonce(), encrypted2.getNonce()));
        // Ciphertexts should be different
        assertFalse(java.util.Arrays.equals(encrypted1.getCiphertext(), encrypted2.getCiphertext()));

        // Both should decrypt to same plaintext
        byte[] decrypted1 = cryptoService.decrypt(key, encrypted1.getCiphertext(), 
                                                 encrypted1.getNonce(), EncryptionAlgorithm.AES_128_GCM);
        byte[] decrypted2 = cryptoService.decrypt(key, encrypted2.getCiphertext(), 
                                                 encrypted2.getNonce(), EncryptionAlgorithm.AES_128_GCM);
        assertEquals(plaintext, new String(decrypted1, StandardCharsets.UTF_8));
        assertEquals(plaintext, new String(decrypted2, StandardCharsets.UTF_8));
    }

    @Test
    void testWrongAlgorithmForDecryption() {
        // Encrypt with AES-128, try to decrypt with AES-256 algorithm spec
        SecretKey key128 = cryptoService.generateKey(EncryptionAlgorithm.AES_128_GCM);
        String plaintext = "Test";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted = cryptoService.encrypt(key128, plaintextBytes, EncryptionAlgorithm.AES_128_GCM);

        // Using wrong algorithm should fail
        assertThrows(Exception.class, () -> {
            SecretKey key256 = cryptoService.generateKey(EncryptionAlgorithm.AES_256_GCM);
            cryptoService.decrypt(key256, encrypted.getCiphertext(), 
                                encrypted.getNonce(), EncryptionAlgorithm.AES_256_GCM);
        });
    }

    @Test
    void testLargeDataEncryption() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_128_GCM);
        
        // Create 1MB of data
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("This is a large test message for encryption. ");
        }
        String largeText = sb.toString();
        byte[] largeData = largeText.getBytes(StandardCharsets.UTF_8);

        EncryptedData encrypted = cryptoService.encrypt(key, largeData, EncryptionAlgorithm.AES_128_GCM);
        byte[] decrypted = cryptoService.decrypt(key, encrypted.getCiphertext(), 
                                                encrypted.getNonce(), EncryptionAlgorithm.AES_128_GCM);

        assertEquals(largeText, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void testEmptyDataEncryption() {
        SecretKey key = cryptoService.generateKey(EncryptionAlgorithm.AES_256_GCM);
        byte[] emptyData = new byte[0];

        EncryptedData encrypted = cryptoService.encrypt(key, emptyData, EncryptionAlgorithm.AES_256_GCM);
        byte[] decrypted = cryptoService.decrypt(key, encrypted.getCiphertext(), 
                                                encrypted.getNonce(), EncryptionAlgorithm.AES_256_GCM);

        assertEquals(0, decrypted.length);
    }
}
