package com.keymanagement.service;

import com.keymanagement.exception.DecryptionException;
import com.keymanagement.exception.EncryptionException;
import com.keymanagement.model.EncryptedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {

    private CryptoService cryptoService;

    @BeforeEach
    void setUp() {
        cryptoService = new CryptoService();
    }

    @Test
    void testGenerateKey_ShouldReturnValidKey() {
        // When
        SecretKey key = cryptoService.generateKey();

        // Then
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes
    }

    @Test
    void testGenerateKey_ShouldReturnDifferentKeys() {
        // When
        SecretKey key1 = cryptoService.generateKey();
        SecretKey key2 = cryptoService.generateKey();

        // Then
        assertNotNull(key1);
        assertNotNull(key2);
        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()));
    }

    @Test
    void testEncrypt_ShouldReturnEncryptedData() {
        // Given
        SecretKey key = cryptoService.generateKey();
        String plaintext = "Hello, World!";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // When
        EncryptedData encryptedData = cryptoService.encrypt(key, plaintextBytes);

        // Then
        assertNotNull(encryptedData);
        assertNotNull(encryptedData.getCiphertext());
        assertNotNull(encryptedData.getNonce());
        assertEquals(12, encryptedData.getNonce().length); // 12 bytes nonce
        assertTrue(encryptedData.getCiphertext().length > 0);
        // Ciphertext should be different from plaintext
        assertFalse(Arrays.equals(plaintextBytes, encryptedData.getCiphertext()));
    }

    @Test
    void testEncrypt_ShouldGenerateUniquenNonces() {
        // Given
        SecretKey key = cryptoService.generateKey();
        String plaintext = "Test data";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        Set<String> nonces = new HashSet<>();

        // When - Encrypt multiple times
        for (int i = 0; i < 100; i++) {
            EncryptedData encryptedData = cryptoService.encrypt(key, plaintextBytes);
            String nonceHex = bytesToHex(encryptedData.getNonce());
            nonces.add(nonceHex);
        }

        // Then - All nonces should be unique
        assertEquals(100, nonces.size(), "All nonces should be unique");
    }

    @Test
    void testEncryptDecrypt_ShouldReturnOriginalPlaintext() {
        // Given
        SecretKey key = cryptoService.generateKey();
        String originalPlaintext = "Sensitive data that needs encryption";
        byte[] plaintextBytes = originalPlaintext.getBytes(StandardCharsets.UTF_8);

        // When
        EncryptedData encryptedData = cryptoService.encrypt(key, plaintextBytes);
        byte[] decryptedBytes = cryptoService.decrypt(key, encryptedData.getCiphertext(), encryptedData.getNonce());
        String decryptedPlaintext = new String(decryptedBytes, StandardCharsets.UTF_8);

        // Then
        assertEquals(originalPlaintext, decryptedPlaintext);
    }

    @Test
    void testDecrypt_WithWrongKey_ShouldThrowDecryptionException() {
        // Given
        SecretKey correctKey = cryptoService.generateKey();
        SecretKey wrongKey = cryptoService.generateKey();
        String plaintext = "Secret message";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        EncryptedData encryptedData = cryptoService.encrypt(correctKey, plaintextBytes);

        // When & Then
        assertThrows(DecryptionException.class, () -> {
            cryptoService.decrypt(wrongKey, encryptedData.getCiphertext(), encryptedData.getNonce());
        });
    }

    @Test
    void testDecrypt_WithWrongNonce_ShouldThrowDecryptionException() {
        // Given
        SecretKey key = cryptoService.generateKey();
        String plaintext = "Secret message";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        EncryptedData encryptedData = cryptoService.encrypt(key, plaintextBytes);
        
        // Create a different nonce
        byte[] wrongNonce = new byte[12];
        Arrays.fill(wrongNonce, (byte) 0xFF);

        // When & Then
        assertThrows(DecryptionException.class, () -> {
            cryptoService.decrypt(key, encryptedData.getCiphertext(), wrongNonce);
        });
    }

    @Test
    void testDecrypt_WithTamperedCiphertext_ShouldThrowDecryptionException() {
        // Given
        SecretKey key = cryptoService.generateKey();
        String plaintext = "Secret message";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        EncryptedData encryptedData = cryptoService.encrypt(key, plaintextBytes);
        
        // Tamper with ciphertext
        byte[] tamperedCiphertext = Arrays.copyOf(encryptedData.getCiphertext(), encryptedData.getCiphertext().length);
        tamperedCiphertext[0] ^= 1; // Flip one bit

        // When & Then
        assertThrows(DecryptionException.class, () -> {
            cryptoService.decrypt(key, tamperedCiphertext, encryptedData.getNonce());
        });
    }

    @Test
    void testEncrypt_WithEmptyPlaintext_ShouldWork() {
        // Given
        SecretKey key = cryptoService.generateKey();
        byte[] emptyPlaintext = new byte[0];

        // When
        EncryptedData encryptedData = cryptoService.encrypt(key, emptyPlaintext);
        byte[] decryptedBytes = cryptoService.decrypt(key, encryptedData.getCiphertext(), encryptedData.getNonce());

        // Then
        assertNotNull(encryptedData);
        assertEquals(0, decryptedBytes.length);
    }

    @Test
    void testEncrypt_WithLargePlaintext_ShouldWork() {
        // Given
        SecretKey key = cryptoService.generateKey();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("Large data block ");
        }
        String largePlaintext = sb.toString();
        byte[] plaintextBytes = largePlaintext.getBytes(StandardCharsets.UTF_8);

        // When
        EncryptedData encryptedData = cryptoService.encrypt(key, plaintextBytes);
        byte[] decryptedBytes = cryptoService.decrypt(key, encryptedData.getCiphertext(), encryptedData.getNonce());
        String decryptedPlaintext = new String(decryptedBytes, StandardCharsets.UTF_8);

        // Then
        assertEquals(largePlaintext, decryptedPlaintext);
    }

    // Helper method to convert bytes to hex string for comparison
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
