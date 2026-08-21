package com.keymanagement.dto;

import jakarta.validation.constraints.NotBlank;

public class EncryptRequest {
    @NotBlank(message = "Plaintext is required")
    private String plaintext;

    public EncryptRequest() {
    }

    public EncryptRequest(String plaintext) {
        this.plaintext = plaintext;
    }

    public String getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(String plaintext) {
        this.plaintext = plaintext;
    }
}
