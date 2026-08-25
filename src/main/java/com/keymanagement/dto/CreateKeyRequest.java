package com.keymanagement.dto;

/**
 * Request DTO for creating a new encryption key.
 * All fields are optional with sensible defaults.
 */
public class CreateKeyRequest {
    
    /**
     * The encryption algorithm to use.
     * Valid values: AES_128_GCM, AES_192_GCM, AES_256_GCM, CHACHA20_POLY1305
     * Default: AES_256_GCM
     */
    private String algorithm;

    /**
     * Optional description for the key.
     */
    private String description;

    // Constructors
    public CreateKeyRequest() {
    }

    public CreateKeyRequest(String algorithm) {
        this.algorithm = algorithm;
    }

    public CreateKeyRequest(String algorithm, String description) {
        this.algorithm = algorithm;
        this.description = description;
    }

    // Getters and Setters
    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
