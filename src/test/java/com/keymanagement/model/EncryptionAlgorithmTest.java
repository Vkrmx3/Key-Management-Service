package com.keymanagement.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionAlgorithmTest {

    @Test
    void testAes128GcmProperties() {
        EncryptionAlgorithm alg = EncryptionAlgorithm.AES_128_GCM;
        assertEquals("AES", alg.getAlgorithm());
        assertEquals("AES/GCM/NoPadding", alg.getTransformation());
        assertEquals(128, alg.getKeySize());
        assertEquals(16, alg.getKeySizeBytes());
        assertEquals(12, alg.getNonceSize());
        assertEquals(128, alg.getTagSize());
        assertEquals("AES-128-GCM", alg.getDisplayName());
    }

    @Test
    void testAes192GcmProperties() {
        EncryptionAlgorithm alg = EncryptionAlgorithm.AES_192_GCM;
        assertEquals("AES", alg.getAlgorithm());
        assertEquals(192, alg.getKeySize());
        assertEquals(24, alg.getKeySizeBytes());
    }

    @Test
    void testAes256GcmProperties() {
        EncryptionAlgorithm alg = EncryptionAlgorithm.AES_256_GCM;
        assertEquals("AES", alg.getAlgorithm());
        assertEquals(256, alg.getKeySize());
        assertEquals(32, alg.getKeySizeBytes());
    }

    @Test
    void testChaCha20Poly1305Properties() {
        EncryptionAlgorithm alg = EncryptionAlgorithm.CHACHA20_POLY1305;
        assertEquals("ChaCha20", alg.getAlgorithm());
        assertEquals("ChaCha20-Poly1305/None/NoPadding", alg.getTransformation());
        assertEquals(256, alg.getKeySize());
        assertEquals(32, alg.getKeySizeBytes());
        assertEquals(12, alg.getNonceSize());
        assertEquals("CHACHA20-POLY1305", alg.getDisplayName());
    }

    @Test
    void testFromString_ValidAlgorithms() {
        assertEquals(EncryptionAlgorithm.AES_128_GCM, 
                    EncryptionAlgorithm.fromString("AES_128_GCM"));
        assertEquals(EncryptionAlgorithm.AES_192_GCM, 
                    EncryptionAlgorithm.fromString("AES_192_GCM"));
        assertEquals(EncryptionAlgorithm.AES_256_GCM, 
                    EncryptionAlgorithm.fromString("AES_256_GCM"));
        assertEquals(EncryptionAlgorithm.CHACHA20_POLY1305, 
                    EncryptionAlgorithm.fromString("CHACHA20_POLY1305"));
    }

    @Test
    void testFromString_CaseInsensitive() {
        assertEquals(EncryptionAlgorithm.AES_256_GCM, 
                    EncryptionAlgorithm.fromString("aes_256_gcm"));
        assertEquals(EncryptionAlgorithm.AES_256_GCM, 
                    EncryptionAlgorithm.fromString("AeS_256_GcM"));
    }

    @Test
    void testFromString_WithDashes() {
        assertEquals(EncryptionAlgorithm.AES_256_GCM, 
                    EncryptionAlgorithm.fromString("AES-256-GCM"));
        assertEquals(EncryptionAlgorithm.CHACHA20_POLY1305, 
                    EncryptionAlgorithm.fromString("ChaCha20-Poly1305"));
    }

    @Test
    void testFromString_NullOrEmpty() {
        // Should return default (AES-256-GCM)
        assertEquals(EncryptionAlgorithm.AES_256_GCM, 
                    EncryptionAlgorithm.fromString(null));
        assertEquals(EncryptionAlgorithm.AES_256_GCM, 
                    EncryptionAlgorithm.fromString(""));
        assertEquals(EncryptionAlgorithm.AES_256_GCM, 
                    EncryptionAlgorithm.fromString("  "));
    }

    @Test
    void testFromString_InvalidAlgorithm() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> EncryptionAlgorithm.fromString("INVALID_ALGORITHM")
        );
        assertTrue(exception.getMessage().contains("Unsupported algorithm"));
        assertTrue(exception.getMessage().contains("INVALID_ALGORITHM"));
    }

    @Test
    void testDisplayName() {
        assertEquals("AES-128-GCM", EncryptionAlgorithm.AES_128_GCM.getDisplayName());
        assertEquals("AES-192-GCM", EncryptionAlgorithm.AES_192_GCM.getDisplayName());
        assertEquals("AES-256-GCM", EncryptionAlgorithm.AES_256_GCM.getDisplayName());
        assertEquals("CHACHA20-POLY1305", EncryptionAlgorithm.CHACHA20_POLY1305.getDisplayName());
    }

    @Test
    void testToString() {
        assertEquals("AES-256-GCM", EncryptionAlgorithm.AES_256_GCM.toString());
        assertEquals("CHACHA20-POLY1305", EncryptionAlgorithm.CHACHA20_POLY1305.toString());
    }
}
