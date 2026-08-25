package com.keymanagement.service;

import com.keymanagement.dto.KeyVersionInfo;
import com.keymanagement.dto.RotateKeyRequest;
import com.keymanagement.dto.RotateKeyResponse;
import com.keymanagement.entity.KeyEntity;
import com.keymanagement.exception.KeyNotFoundException;
import com.keymanagement.model.EncryptedData;
import com.keymanagement.repository.KeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class KeyRotationServiceTest {

    @Mock
    private KeyRepository keyRepository;

    @Mock
    private CryptoService cryptoService;

    @Mock
    private KeyStorageService keyStorageService;

    @InjectMocks
    private KeyRotationService keyRotationService;

    private KeyEntity mockCurrentVersion;
    private SecretKey mockSecretKey;

    @BeforeEach
    void setUp() {
        mockCurrentVersion = new KeyEntity(
                "key-uuid-1",
                "logical-key-1",
                1,
                new byte[]{1, 2, 3, 4},
                "AES",
                256
        );
        mockCurrentVersion.setCreatedAt(LocalDateTime.now());
        mockCurrentVersion.setCurrentVersion(true);

        mockSecretKey = mock(SecretKey.class);
        when(mockSecretKey.getEncoded()).thenReturn(new byte[]{5, 6, 7, 8});
        when(mockSecretKey.getAlgorithm()).thenReturn("AES");
    }

    @Test
    void testRotateKey_Success() {
        // Arrange
        String logicalKeyId = "logical-key-1";
        RotateKeyRequest request = new RotateKeyRequest("Scheduled rotation");

        when(keyRepository.findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId))
                .thenReturn(Optional.of(mockCurrentVersion));
        when(keyRepository.findMaxVersionByLogicalKeyId(logicalKeyId))
                .thenReturn(1);
        when(cryptoService.generateKey()).thenReturn(mockSecretKey);
        when(keyRepository.save(any(KeyEntity.class))).thenAnswer(i -> i.getArguments()[0]);

        // Act
        RotateKeyResponse response = keyRotationService.rotateKey(logicalKeyId, request);

        // Assert
        assertNotNull(response);
        assertEquals(logicalKeyId, response.getLogicalKeyId());
        assertEquals(1, response.getOldVersion());
        assertEquals(2, response.getNewVersion());
        assertNotNull(response.getNewKeyId());

        // Verify old version was updated
        assertFalse(mockCurrentVersion.getCurrentVersion());
        assertNotNull(mockCurrentVersion.getRotatedAt());
        assertEquals("Scheduled rotation", mockCurrentVersion.getRotationReason());

        // Verify new version was created
        verify(keyRepository, times(2)).save(any(KeyEntity.class));
    }

    @Test
    void testRotateKey_KeyNotFound() {
        // Arrange
        String logicalKeyId = "non-existent-key";
        RotateKeyRequest request = new RotateKeyRequest();

        when(keyRepository.findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(KeyNotFoundException.class, () -> 
            keyRotationService.rotateKey(logicalKeyId, request)
        );

        verify(keyRepository, never()).save(any(KeyEntity.class));
    }

    @Test
    void testGetKeyVersions_Success() {
        // Arrange
        String logicalKeyId = "logical-key-1";
        
        KeyEntity version1 = new KeyEntity("key-1", logicalKeyId, 1, new byte[]{1}, "AES", 256);
        version1.setCreatedAt(LocalDateTime.now().minusDays(2));
        version1.setCurrentVersion(false);
        
        KeyEntity version2 = new KeyEntity("key-2", logicalKeyId, 2, new byte[]{2}, "AES", 256);
        version2.setCreatedAt(LocalDateTime.now());
        version2.setCurrentVersion(true);

        when(keyRepository.findByLogicalKeyIdAndActiveTrueOrderByVersionDesc(logicalKeyId))
                .thenReturn(Arrays.asList(version2, version1));

        // Act
        List<KeyVersionInfo> versions = keyRotationService.getKeyVersions(logicalKeyId);

        // Assert
        assertNotNull(versions);
        assertEquals(2, versions.size());
        assertEquals(2, versions.get(0).getVersion());
        assertTrue(versions.get(0).getCurrentVersion());
        assertEquals(1, versions.get(1).getVersion());
        assertFalse(versions.get(1).getCurrentVersion());
    }

    @Test
    void testGetKeyVersions_KeyNotFound() {
        // Arrange
        String logicalKeyId = "non-existent-key";
        when(keyRepository.findByLogicalKeyIdAndActiveTrueOrderByVersionDesc(logicalKeyId))
                .thenReturn(Arrays.asList());

        // Act & Assert
        assertThrows(KeyNotFoundException.class, () -> 
            keyRotationService.getKeyVersions(logicalKeyId)
        );
    }

    @Test
    void testGetCurrentVersion_Success() {
        // Arrange
        String logicalKeyId = "logical-key-1";
        when(keyRepository.findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId))
                .thenReturn(Optional.of(mockCurrentVersion));

        // Act
        KeyVersionInfo currentVersion = keyRotationService.getCurrentVersion(logicalKeyId);

        // Assert
        assertNotNull(currentVersion);
        assertEquals(logicalKeyId, currentVersion.getLogicalKeyId());
        assertEquals(1, currentVersion.getVersion());
        assertTrue(currentVersion.getCurrentVersion());
    }

    @Test
    void testGetCurrentVersion_KeyNotFound() {
        // Arrange
        String logicalKeyId = "non-existent-key";
        when(keyRepository.findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(KeyNotFoundException.class, () -> 
            keyRotationService.getCurrentVersion(logicalKeyId)
        );
    }

    @Test
    void testReEncryptData_Success() {
        // Arrange
        String logicalKeyId = "logical-key-1";
        Integer oldVersion = 1;
        
        KeyEntity oldKeyEntity = new KeyEntity("key-1", logicalKeyId, 1, 
                new byte[]{1, 2, 3, 4}, "AES", 256);
        KeyEntity currentKeyEntity = new KeyEntity("key-2", logicalKeyId, 2, 
                new byte[]{5, 6, 7, 8}, "AES", 256);
        currentKeyEntity.setCurrentVersion(true);

        EncryptedData oldEncryptedData = new EncryptedData(
                new byte[]{10, 20, 30}, 
                new byte[]{40, 50, 60}
        );
        
        byte[] decryptedPlaintext = "test data".getBytes();
        EncryptedData newEncryptedData = new EncryptedData(
                new byte[]{70, 80, 90}, 
                new byte[]{100, 110, 120}
        );

        SecretKey oldKey = mock(SecretKey.class);
        SecretKey currentKey = mock(SecretKey.class);

        when(keyRepository.findByLogicalKeyIdAndVersionAndActiveTrue(logicalKeyId, oldVersion))
                .thenReturn(Optional.of(oldKeyEntity));
        when(keyRepository.findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId))
                .thenReturn(Optional.of(currentKeyEntity));
        when(keyStorageService.reconstructSecretKey(oldKeyEntity.getKeyMaterial(), "AES"))
                .thenReturn(oldKey);
        when(keyStorageService.reconstructSecretKey(currentKeyEntity.getKeyMaterial(), "AES"))
                .thenReturn(currentKey);
        when(cryptoService.decrypt(oldKey, oldEncryptedData.getCiphertext(), oldEncryptedData.getNonce()))
                .thenReturn(decryptedPlaintext);
        when(cryptoService.encrypt(currentKey, decryptedPlaintext))
                .thenReturn(newEncryptedData);

        // Act
        EncryptedData result = keyRotationService.reEncryptData(logicalKeyId, oldVersion, oldEncryptedData);

        // Assert
        assertNotNull(result);
        assertArrayEquals(newEncryptedData.getCiphertext(), result.getCiphertext());
        assertArrayEquals(newEncryptedData.getNonce(), result.getNonce());
        
        verify(cryptoService).decrypt(oldKey, oldEncryptedData.getCiphertext(), oldEncryptedData.getNonce());
        verify(cryptoService).encrypt(currentKey, decryptedPlaintext);
    }

    @Test
    void testReEncryptData_OldVersionNotFound() {
        // Arrange
        String logicalKeyId = "logical-key-1";
        Integer oldVersion = 999;
        EncryptedData encryptedData = new EncryptedData(new byte[]{1}, new byte[]{2});

        when(keyRepository.findByLogicalKeyIdAndVersionAndActiveTrue(logicalKeyId, oldVersion))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(KeyNotFoundException.class, () -> 
            keyRotationService.reEncryptData(logicalKeyId, oldVersion, encryptedData)
        );
    }

    @Test
    void testReEncryptData_CurrentVersionNotFound() {
        // Arrange
        String logicalKeyId = "logical-key-1";
        Integer oldVersion = 1;
        
        KeyEntity oldKeyEntity = new KeyEntity("key-1", logicalKeyId, 1, 
                new byte[]{1, 2, 3, 4}, "AES", 256);
        
        EncryptedData encryptedData = new EncryptedData(new byte[]{1}, new byte[]{2});
        SecretKey oldKey = mock(SecretKey.class);

        when(keyRepository.findByLogicalKeyIdAndVersionAndActiveTrue(logicalKeyId, oldVersion))
                .thenReturn(Optional.of(oldKeyEntity));
        when(keyStorageService.reconstructSecretKey(any(), anyString()))
                .thenReturn(oldKey);
        when(cryptoService.decrypt(any(), any(), any()))
                .thenReturn(new byte[]{1, 2, 3});
        when(keyRepository.findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(logicalKeyId))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(KeyNotFoundException.class, () -> 
            keyRotationService.reEncryptData(logicalKeyId, oldVersion, encryptedData)
        );
    }
}
