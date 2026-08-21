package com.keymanagement.dto;

import jakarta.validation.constraints.NotBlank;

public class DecryptRequest {
    @NotBlank(message = "Ciphertext is required")
    private String ciphertext;

    @NotBlank(message = "Nonce is required")
    private String nonce;

    public DecryptRequest() {
    }

    public DecryptRequest(String ciphertext, String nonce) {
        this.ciphertext = ciphertext;
        this.nonce = nonce;
    }

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
}
