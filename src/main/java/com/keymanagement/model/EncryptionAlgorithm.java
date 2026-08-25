package com.keymanagement.model;

/**
 * Supported encryption algorithms for the KMS.
 * Each algorithm has specific key size requirements and security properties.
 */
public enum EncryptionAlgorithm {
    /**
     * AES-128-GCM: 128-bit AES in Galois/Counter Mode
     * - Key Size: 128 bits (16 bytes)
     * - Security Level: High
     * - Performance: Fastest AES variant
     * - Use Case: General purpose, high-throughput scenarios
     */
    AES_128_GCM("AES", "AES/GCM/NoPadding", 128, 12, 128),

    /**
     * AES-192-GCM: 192-bit AES in Galois/Counter Mode
     * - Key Size: 192 bits (24 bytes)
     * - Security Level: Very High
     * - Performance: Moderate
     * - Use Case: Enhanced security requirements
     */
    AES_192_GCM("AES", "AES/GCM/NoPadding", 192, 12, 128),

    /**
     * AES-256-GCM: 256-bit AES in Galois/Counter Mode (DEFAULT)
     * - Key Size: 256 bits (32 bytes)
     * - Security Level: Maximum
     * - Performance: Slowest AES variant (minimal difference)
     * - Use Case: Maximum security, compliance requirements
     */
    AES_256_GCM("AES", "AES/GCM/NoPadding", 256, 12, 128),

    /**
     * ChaCha20-Poly1305: Modern stream cipher with AEAD
     * - Key Size: 256 bits (32 bytes)
     * - Security Level: Maximum
     * - Performance: Excellent on software (no AES-NI needed)
     * - Use Case: Mobile devices, non-AES hardware
     */
    CHACHA20_POLY1305("ChaCha20", "ChaCha20-Poly1305/None/NoPadding", 256, 12, 128);

    private final String algorithm;
    private final String transformation;
    private final int keySize;
    private final int nonceSize;
    private final int tagSize;

    EncryptionAlgorithm(String algorithm, String transformation, int keySize, int nonceSize, int tagSize) {
        this.algorithm = algorithm;
        this.transformation = transformation;
        this.keySize = keySize;
        this.nonceSize = nonceSize;
        this.tagSize = tagSize;
    }

    /**
     * Get the base algorithm name (e.g., "AES", "ChaCha20").
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Get the full transformation string for Cipher (e.g., "AES/GCM/NoPadding").
     */
    public String getTransformation() {
        return transformation;
    }

    /**
     * Get the key size in bits.
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Get the key size in bytes.
     */
    public int getKeySizeBytes() {
        return keySize / 8;
    }

    /**
     * Get the nonce/IV size in bytes.
     */
    public int getNonceSize() {
        return nonceSize;
    }

    /**
     * Get the authentication tag size in bits.
     */
    public int getTagSize() {
        return tagSize;
    }

    /**
     * Parse algorithm from string name.
     *
     * @param name Algorithm name (case-insensitive)
     * @return EncryptionAlgorithm enum value
     * @throws IllegalArgumentException if algorithm is not supported
     */
    public static EncryptionAlgorithm fromString(String name) {
        if (name == null || name.trim().isEmpty()) {
            return AES_256_GCM; // Default
        }

        String normalized = name.trim().toUpperCase().replace("-", "_");
        
        try {
            return EncryptionAlgorithm.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Unsupported algorithm: " + name + ". Supported: AES_128_GCM, AES_192_GCM, AES_256_GCM, CHACHA20_POLY1305"
            );
        }
    }

    /**
     * Get display name for UI/API responses.
     */
    public String getDisplayName() {
        return this.name().replace("_", "-");
    }

    @Override
    public String toString() {
        return getDisplayName();
    }
}
