package com.keymanagement.dto;

public class CreateKeyResponse {
    private String keyId;

    public CreateKeyResponse() {
    }

    public CreateKeyResponse(String keyId) {
        this.keyId = keyId;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
