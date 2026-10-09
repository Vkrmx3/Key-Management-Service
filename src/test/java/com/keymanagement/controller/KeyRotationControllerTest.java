package com.keymanagement.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keymanagement.dto.KeyVersionInfo;
import com.keymanagement.dto.RotateKeyRequest;
import com.keymanagement.dto.RotateKeyResponse;
import com.keymanagement.service.KeyRotationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(KeyRotationController.class)
@Import(TestSecurityConfig.class)
class KeyRotationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private KeyRotationService keyRotationService;

    private String logicalKeyId;
    private RotateKeyResponse mockRotateResponse;
    private List<KeyVersionInfo> mockVersions;

    @BeforeEach
    void setUp() {
        logicalKeyId = "logical-key-1";
        
        mockRotateResponse = new RotateKeyResponse(
                logicalKeyId,
                1,
                2,
                "new-key-uuid"
        );

        KeyVersionInfo version1 = new KeyVersionInfo();
        version1.setKeyId("key-1");
        version1.setLogicalKeyId(logicalKeyId);
        version1.setVersion(1);
        version1.setCurrentVersion(false);
        version1.setAlgorithm("AES");
        version1.setKeySize(256);
        version1.setCreatedAt(LocalDateTime.now().minusDays(2));
        version1.setActive(true);

        KeyVersionInfo version2 = new KeyVersionInfo();
        version2.setKeyId("key-2");
        version2.setLogicalKeyId(logicalKeyId);
        version2.setVersion(2);
        version2.setCurrentVersion(true);
        version2.setAlgorithm("AES");
        version2.setKeySize(256);
        version2.setCreatedAt(LocalDateTime.now());
        version2.setActive(true);

        mockVersions = Arrays.asList(version2, version1);
    }

    @Test
    void testRotateKey_WithReason() throws Exception {
        // Arrange
        RotateKeyRequest request = new RotateKeyRequest("Scheduled rotation");
        when(keyRotationService.rotateKey(anyString(), any(RotateKeyRequest.class)))
                .thenReturn(mockRotateResponse);

        // Act & Assert
        mockMvc.perform(post("/api/keys/{logicalKeyId}/rotate", logicalKeyId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.logicalKeyId").value(logicalKeyId))
                .andExpect(jsonPath("$.oldVersion").value(1))
                .andExpect(jsonPath("$.newVersion").value(2))
                .andExpect(jsonPath("$.newKeyId").value("new-key-uuid"))
                .andExpect(jsonPath("$.message").value("Key rotated successfully"));
    }

    @Test
    void testRotateKey_WithoutReason() throws Exception {
        // Arrange
        when(keyRotationService.rotateKey(anyString(), any()))
                .thenReturn(mockRotateResponse);

        // Act & Assert
        mockMvc.perform(post("/api/keys/{logicalKeyId}/rotate", logicalKeyId)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.logicalKeyId").value(logicalKeyId))
                .andExpect(jsonPath("$.oldVersion").value(1))
                .andExpect(jsonPath("$.newVersion").value(2));
    }

    @Test
    void testGetKeyVersions() throws Exception {
        // Arrange
        when(keyRotationService.getKeyVersions(logicalKeyId))
                .thenReturn(mockVersions);

        // Act & Assert
        mockMvc.perform(get("/api/keys/{logicalKeyId}/versions", logicalKeyId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].version").value(2))
                .andExpect(jsonPath("$[0].currentVersion").value(true))
                .andExpect(jsonPath("$[1].version").value(1))
                .andExpect(jsonPath("$[1].currentVersion").value(false));
    }

    @Test
    void testGetCurrentVersion() throws Exception {
        // Arrange
        KeyVersionInfo currentVersion = mockVersions.get(0); // version 2
        when(keyRotationService.getCurrentVersion(logicalKeyId))
                .thenReturn(currentVersion);

        // Act & Assert
        mockMvc.perform(get("/api/keys/{logicalKeyId}/current-version", logicalKeyId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.logicalKeyId").value(logicalKeyId))
                .andExpect(jsonPath("$.version").value(2))
                .andExpect(jsonPath("$.currentVersion").value(true))
                .andExpect(jsonPath("$.algorithm").value("AES"))
                .andExpect(jsonPath("$.keySize").value(256));
    }
}
