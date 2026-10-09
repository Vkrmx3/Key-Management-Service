package com.keymanagement.dto;

import jakarta.validation.constraints.Size;

/**
 * Request DTO for key rotation.
 */
public class RotateKeyRequest {

    @Size(max = 500, message = "Rotation reason must not exceed 500 characters")
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
