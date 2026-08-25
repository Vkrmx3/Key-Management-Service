package com.keymanagement.dto;

import java.util.List;

/**
 * Response DTO for key rotation operation.
 */
public class RotateKeyResponse {

    private String logicalKeyId;
    private Integer oldVersion;
    private Integer newVersion;
    private String newKeyId;
    private String message;
    private List<String> warnings;

    // Constructors
    public RotateKeyResponse() {
    }

    public RotateKeyResponse(String logicalKeyId, Integer oldVersion, Integer newVersion, String newKeyId) {
        this.logicalKeyId = logicalKeyId;
        this.oldVersion = oldVersion;
        this.newVersion = newVersion;
        this.newKeyId = newKeyId;
        this.message = "Key rotated successfully";
    }

    // Getters and Setters
    public String getLogicalKeyId() {
        return logicalKeyId;
    }

    public void setLogicalKeyId(String logicalKeyId) {
        this.logicalKeyId = logicalKeyId;
    }

    public Integer getOldVersion() {
        return oldVersion;
    }

    public void setOldVersion(Integer oldVersion) {
        this.oldVersion = oldVersion;
    }

    public Integer getNewVersion() {
        return newVersion;
    }

    public void setNewVersion(Integer newVersion) {
        this.newVersion = newVersion;
    }

    public String getNewKeyId() {
        return newKeyId;
    }

    public void setNewKeyId(String newKeyId) {
        this.newKeyId = newKeyId;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }
}
