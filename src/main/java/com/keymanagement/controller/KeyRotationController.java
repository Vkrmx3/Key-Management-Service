package com.keymanagement.controller;

import com.keymanagement.dto.KeyVersionInfo;
import com.keymanagement.dto.RotateKeyRequest;
import com.keymanagement.dto.RotateKeyResponse;
import com.keymanagement.service.KeyRotationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller for key rotation operations.
 * Handles key versioning, rotation, and version management.
 */
@RestController
@RequestMapping("/api/keys")
public class KeyRotationController {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotationController.class);

    private final KeyRotationService keyRotationService;

    @Autowired
    public KeyRotationController(KeyRotationService keyRotationService) {
        this.keyRotationService = keyRotationService;
    }

    /**
     * Rotate a key to create a new version.
     * The old version remains available for decryption but new encryptions use the new version.
     *
     * @param logicalKeyId The logical key identifier
     * @param request Optional rotation request with reason
     * @return Rotation response with version information
     */
    @PostMapping("/{logicalKeyId}/rotate")
    public ResponseEntity<RotateKeyResponse> rotateKey(
            @PathVariable String logicalKeyId,
            @RequestBody(required = false) RotateKeyRequest request) {
        
        logger.info("Key rotation request received for logical key: {}", logicalKeyId);
        
        RotateKeyResponse response = keyRotationService.rotateKey(logicalKeyId, request);
        
        logger.info("Key rotated successfully: {} from v{} to v{}", 
                   logicalKeyId, response.getOldVersion(), response.getNewVersion());
        
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Get all versions of a key.
     *
     * @param logicalKeyId The logical key identifier
     * @return List of all key versions
     */
    @GetMapping("/{logicalKeyId}/versions")
    public ResponseEntity<List<KeyVersionInfo>> getKeyVersions(@PathVariable String logicalKeyId) {
        logger.info("Retrieving versions for logical key: {}", logicalKeyId);
        
        List<KeyVersionInfo> versions = keyRotationService.getKeyVersions(logicalKeyId);
        
        logger.info("Retrieved {} versions for logical key: {}", versions.size(), logicalKeyId);
        
        return ResponseEntity.ok(versions);
    }

    /**
     * Get the current version of a key.
     *
     * @param logicalKeyId The logical key identifier
     * @return Current version information
     */
    @GetMapping("/{logicalKeyId}/current-version")
    public ResponseEntity<KeyVersionInfo> getCurrentVersion(@PathVariable String logicalKeyId) {
        logger.info("Retrieving current version for logical key: {}", logicalKeyId);
        
        KeyVersionInfo currentVersion = keyRotationService.getCurrentVersion(logicalKeyId);
        
        logger.info("Current version for {}: v{}", logicalKeyId, currentVersion.getVersion());
        
        return ResponseEntity.ok(currentVersion);
    }
}
