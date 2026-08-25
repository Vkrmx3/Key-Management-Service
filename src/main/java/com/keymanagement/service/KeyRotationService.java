package com.keymanagement.service;

import com.keymanagement.dto.KeyVersionInfo;
import com.keymanagement.dto.RotateKeyRequest;
import com.keymanagement.dto.RotateKeyResponse;
import com.keymanagement.entity.KeyEntity;
import com.keymanagement.exception.KeyNotFoundException;
import com.keymanagement.model.EncryptedData;
import com.keymanagement.repository.KeyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for key rotation and version management.
 * Handles creating new versions of keys and managing the version lifecycle.
 */
@Service
public class KeyRotationService {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotationService.class);

    private final KeyRepository keyRepository;
    private final CryptoService cryptoService;
    private final KeyStorageService keyStorageService;

    @Autowired
    public KeyRotationService(KeyRepository keyRepository, 
                             CryptoService cryptoService,
                             KeyStorageService keyStorageService) {
        this.keyRepository = keyRepository;
        this.cryptoService = cryptoService;
        this.keyStorageService = keyStorageService;
    }

    /**
     * Rotate a key by creating a new version.
     * The old version is marked as non-current but remains active for decryption.
     *
     * @param logicalKeyId The logical key identifier
     * @param request Rotation request with optional reason
     * @return Rotation response with version information
     */
    @Transactional
    public RotateKeyResponse rotateKey(String logicalKeyId, RotateKeyRequest request) {
        logger.info("Rotating key with logical ID: {}", logicalKeyId);

        // Find the current version
        KeyEntity currentVersion = keyRepository
                .findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId)
                .orElseThrow(() -> new KeyNotFoundException("Key not found: " + logicalKeyId));

        // Get the next version number
        Integer maxVersion = keyRepository.findMaxVersionByLogicalKeyId(logicalKeyId);
        Integer newVersionNumber = (maxVersion != null ? maxVersion : currentVersion.getVersion()) + 1;

        // Mark current version as not current
        currentVersion.setCurrentVersion(false);
        currentVersion.setRotatedAt(LocalDateTime.now());
        if (request != null && request.getReason() != null) {
            currentVersion.setRotationReason(request.getReason());
        }
        keyRepository.save(currentVersion);

        // Generate new key material
        SecretKey newKey = cryptoService.generateKey();
        String newKeyId = UUID.randomUUID().toString();

        // Create new version
        KeyEntity newVersion = new KeyEntity(
                newKeyId,
                logicalKeyId,
                newVersionNumber,
                newKey.getEncoded(),
                currentVersion.getAlgorithm(),
                currentVersion.getKeySize()
        );
        newVersion.setCurrentVersion(true);
        newVersion.setDescription("Rotated from version " + currentVersion.getVersion());
        
        keyRepository.save(newVersion);

        logger.info("Key rotated successfully. Logical ID: {}, Old version: {}, New version: {}", 
                   logicalKeyId, currentVersion.getVersion(), newVersionNumber);

        RotateKeyResponse response = new RotateKeyResponse(
                logicalKeyId,
                currentVersion.getVersion(),
                newVersionNumber,
                newKeyId
        );
        
        return response;
    }

    /**
     * Get all versions of a key.
     *
     * @param logicalKeyId The logical key identifier
     * @return List of key version information
     */
    @Transactional(readOnly = true)
    public List<KeyVersionInfo> getKeyVersions(String logicalKeyId) {
        logger.debug("Retrieving all versions for logical key: {}", logicalKeyId);

        List<KeyEntity> versions = keyRepository.findByLogicalKeyIdAndActiveTrueOrderByVersionDesc(logicalKeyId);
        
        if (versions.isEmpty()) {
            throw new KeyNotFoundException("Key not found: " + logicalKeyId);
        }

        return versions.stream()
                .map(this::toKeyVersionInfo)
                .collect(Collectors.toList());
    }

    /**
     * Get the current version of a key.
     *
     * @param logicalKeyId The logical key identifier
     * @return Current version information
     */
    @Transactional(readOnly = true)
    public KeyVersionInfo getCurrentVersion(String logicalKeyId) {
        logger.debug("Retrieving current version for logical key: {}", logicalKeyId);

        KeyEntity currentVersion = keyRepository
                .findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId)
                .orElseThrow(() -> new KeyNotFoundException("Key not found: " + logicalKeyId));

        return toKeyVersionInfo(currentVersion);
    }

    /**
     * Re-encrypt data from one key version to another.
     * Typically used to migrate data from an old version to the current version.
     *
     * @param logicalKeyId The logical key identifier
     * @param oldVersion The version used to encrypt the data
     * @param encryptedData The encrypted data to re-encrypt
     * @return Newly encrypted data with current version
     */
    @Transactional(readOnly = true)
    public EncryptedData reEncryptData(String logicalKeyId, Integer oldVersion, EncryptedData encryptedData) {
        logger.info("Re-encrypting data from version {} to current version for key: {}", oldVersion, logicalKeyId);

        // Get the old version key
        KeyEntity oldKeyEntity = keyRepository
                .findByLogicalKeyIdAndVersionAndActiveTrue(logicalKeyId, oldVersion)
                .orElseThrow(() -> new KeyNotFoundException(
                        "Key version not found: " + logicalKeyId + " v" + oldVersion));

        SecretKey oldKey = keyStorageService.reconstructSecretKey(
                oldKeyEntity.getKeyMaterial(), 
                oldKeyEntity.getAlgorithm()
        );

        // Decrypt with old version
        byte[] plaintext = cryptoService.decrypt(
                oldKey, 
                encryptedData.getCiphertext(), 
                encryptedData.getNonce()
        );

        // Get the current version key
        KeyEntity currentKeyEntity = keyRepository
                .findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId)
                .orElseThrow(() -> new KeyNotFoundException(
                        "Current key version not found: " + logicalKeyId));

        SecretKey currentKey = keyStorageService.reconstructSecretKey(
                currentKeyEntity.getKeyMaterial(),
                currentKeyEntity.getAlgorithm()
        );

        // Encrypt with current version
        EncryptedData newEncryptedData = cryptoService.encrypt(currentKey, plaintext);

        logger.info("Data re-encrypted successfully from v{} to v{}", oldVersion, currentKeyEntity.getVersion());

        return newEncryptedData;
    }

    /**
     * Convert KeyEntity to KeyVersionInfo DTO.
     */
    private KeyVersionInfo toKeyVersionInfo(KeyEntity entity) {
        KeyVersionInfo info = new KeyVersionInfo();
        info.setKeyId(entity.getKeyId());
        info.setLogicalKeyId(entity.getLogicalKeyId());
        info.setVersion(entity.getVersion());
        info.setCurrentVersion(entity.getCurrentVersion());
        info.setAlgorithm(entity.getAlgorithm());
        info.setKeySize(entity.getKeySize());
        info.setCreatedAt(entity.getCreatedAt());
        info.setRotatedAt(entity.getRotatedAt());
        info.setRotationReason(entity.getRotationReason());
        info.setActive(entity.getActive());
        return info;
    }
}
