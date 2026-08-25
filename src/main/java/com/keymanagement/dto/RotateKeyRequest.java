package com.keymanagement.dto;

/**
 * Request DTO for key rotation.
 */
public class RotateKeyRequest {

    private String reason;

    // Constructors
    public RotateKeyRequest() {
    }

    public RotateKeyRequest(String reason) {
        this.reason = reason;
    }

    // Getters and Setters
    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
