package com.keymanagement.dto;

/**
 * Response DTO for key creation.
 */
public class CreateKeyResponse {

    private String keyId;
    private String algorithm;
    private Integer keySize;

    public CreateKeyResponse() {
    }

    public CreateKeyResponse(String keyId) {
        this.keyId = keyId;
    }

    public CreateKeyResponse(String keyId, String algorithm, Integer keySize) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keySize = keySize;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }
}
