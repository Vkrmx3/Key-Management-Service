package com.keymanagement.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for re-encrypting data with a new key version.
 */
public class ReEncryptRequest {

    @NotBlank(message = "Ciphertext is required")
    private String ciphertext;

    @NotBlank(message = "Nonce is required")
    private String nonce;

    private Integer sourceVersion;

    // Constructors
    public ReEncryptRequest() {
    }

    public ReEncryptRequest(String ciphertext, String nonce, Integer sourceVersion) {
        this.ciphertext = ciphertext;
        this.nonce = nonce;
        this.sourceVersion = sourceVersion;
    }

    // Getters and Setters
    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public Integer getSourceVersion() {
        return sourceVersion;
    }

    public void setSourceVersion(Integer sourceVersion) {
        this.sourceVersion = sourceVersion;
    }
}
