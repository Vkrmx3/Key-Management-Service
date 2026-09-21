package com.keymanagement.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keymanagement.dto.DecryptRequest;
import com.keymanagement.dto.EncryptRequest;
import com.keymanagement.exception.DecryptionException;
import com.keymanagement.exception.KeyNotFoundException;
import com.keymanagement.model.EncryptedData;
import com.keymanagement.service.KeyManagementService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Base64;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(KeyManagementController.class)
@Import(TestSecurityConfig.class)
@WithMockUser(username = "testuser", roles = {"USER"})
class KeyManagementControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // Note: @MockBean is deprecated in Spring Boot 3.4+ but is still the recommended
    // approach for @WebMvcTest slices until Spring provides a stable alternative
    @SuppressWarnings("removal")
    @MockBean
    private KeyManagementService keyManagementService;

    @Test
    void testCreateKey_ShouldReturnKeyId() throws Exception {
        // Given
        String expectedKeyId = "550e8400-e29b-41d4-a716-446655440000";
        when(keyManagementService.createKey()).thenReturn(expectedKeyId);

        // When & Then
        mockMvc.perform(post("/api/keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").value(expectedKeyId));

        verify(keyManagementService, times(1)).createKey();
    }

    @Test
    void testCreateKey_WithEmptyBody_ShouldWork() throws Exception {
        // Given
        String expectedKeyId = "550e8400-e29b-41d4-a716-446655440001";
        when(keyManagementService.createKey()).thenReturn(expectedKeyId);

        // When & Then
        mockMvc.perform(post("/api/keys")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").value(expectedKeyId));

        verify(keyManagementService, times(1)).createKey();
    }

    @Test
    void testEncrypt_ShouldReturnCiphertextAndNonce() throws Exception {
        // Given
        String keyId = "550e8400-e29b-41d4-a716-446655440000";
        String plaintext = "Hello, World!";
        byte[] mockCiphertext = "encrypted-data".getBytes();
        byte[] mockNonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        EncryptedData mockEncryptedData = new EncryptedData(mockCiphertext, mockNonce);

        EncryptRequest request = new EncryptRequest(plaintext);
        when(keyManagementService.encryptData(eq(keyId), eq(plaintext))).thenReturn(mockEncryptedData);

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/encrypt", keyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ciphertext").value(Base64.getEncoder().encodeToString(mockCiphertext)))
                .andExpect(jsonPath("$.nonce").value(Base64.getEncoder().encodeToString(mockNonce)));

        verify(keyManagementService, times(1)).encryptData(keyId, plaintext);
    }

    @Test
    void testEncrypt_WithMissingPlaintext_ShouldReturnBadRequest() throws Exception {
        // Given
        String keyId = "550e8400-e29b-41d4-a716-446655440000";
        EncryptRequest request = new EncryptRequest(); // No plaintext

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/encrypt", keyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Plaintext is required")));

        verify(keyManagementService, never()).encryptData(any(), any());
    }

    @Test
    void testEncrypt_WithInvalidKeyId_ShouldReturnNotFound() throws Exception {
        // Given
        String invalidKeyId = "invalid-key-id";
        String plaintext = "Test data";
        EncryptRequest request = new EncryptRequest(plaintext);

        when(keyManagementService.encryptData(eq(invalidKeyId), eq(plaintext)))
                .thenThrow(new KeyNotFoundException(invalidKeyId));

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/encrypt", invalidKeyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value(containsString(invalidKeyId)));

        verify(keyManagementService, times(1)).encryptData(invalidKeyId, plaintext);
    }

    @Test
    void testDecrypt_ShouldReturnPlaintext() throws Exception {
        // Given
        String keyId = "550e8400-e29b-41d4-a716-446655440000";
        String expectedPlaintext = "Hello, World!";
        String ciphertextB64 = Base64.getEncoder().encodeToString("encrypted-data".getBytes());
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});

        DecryptRequest request = new DecryptRequest(ciphertextB64, nonceB64);
        when(keyManagementService.decryptData(eq(keyId), eq(ciphertextB64), eq(nonceB64)))
                .thenReturn(expectedPlaintext);

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/decrypt", keyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value(expectedPlaintext));

        verify(keyManagementService, times(1)).decryptData(keyId, ciphertextB64, nonceB64);
    }

    @Test
    void testDecrypt_WithMissingCiphertext_ShouldReturnBadRequest() throws Exception {
        // Given
        String keyId = "550e8400-e29b-41d4-a716-446655440000";
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);
        DecryptRequest request = new DecryptRequest(null, nonceB64); // Missing ciphertext

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/decrypt", keyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Ciphertext is required")));

        verify(keyManagementService, never()).decryptData(any(), any(), any());
    }

    @Test
    void testDecrypt_WithMissingNonce_ShouldReturnBadRequest() throws Exception {
        // Given
        String keyId = "550e8400-e29b-41d4-a716-446655440000";
        String ciphertextB64 = Base64.getEncoder().encodeToString("encrypted".getBytes());
        DecryptRequest request = new DecryptRequest(ciphertextB64, null); // Missing nonce

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/decrypt", keyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Nonce is required")));

        verify(keyManagementService, never()).decryptData(any(), any(), any());
    }

    @Test
    void testDecrypt_WithInvalidKeyId_ShouldReturnNotFound() throws Exception {
        // Given
        String invalidKeyId = "invalid-key-id";
        String ciphertextB64 = Base64.getEncoder().encodeToString("encrypted".getBytes());
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);

        DecryptRequest request = new DecryptRequest(ciphertextB64, nonceB64);
        when(keyManagementService.decryptData(eq(invalidKeyId), eq(ciphertextB64), eq(nonceB64)))
                .thenThrow(new KeyNotFoundException(invalidKeyId));

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/decrypt", invalidKeyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value(containsString(invalidKeyId)));

        verify(keyManagementService, times(1)).decryptData(invalidKeyId, ciphertextB64, nonceB64);
    }

    @Test
    void testDecrypt_WithInvalidCiphertext_ShouldReturnBadRequest() throws Exception {
        // Given
        String keyId = "550e8400-e29b-41d4-a716-446655440000";
        String ciphertextB64 = Base64.getEncoder().encodeToString("tampered".getBytes());
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);

        DecryptRequest request = new DecryptRequest(ciphertextB64, nonceB64);
        when(keyManagementService.decryptData(eq(keyId), eq(ciphertextB64), eq(nonceB64)))
                .thenThrow(new DecryptionException("Decryption failed"));

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/decrypt", keyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Decryption failed. Invalid ciphertext, nonce, or key."));

        verify(keyManagementService, times(1)).decryptData(keyId, ciphertextB64, nonceB64);
    }

    @Test
    void testDecrypt_WithInvalidBase64_ShouldReturnBadRequest() throws Exception {
        // Given
        String keyId = "550e8400-e29b-41d4-a716-446655440000";
        String invalidBase64 = "not-valid-base64!!!";
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);

        DecryptRequest request = new DecryptRequest(invalidBase64, nonceB64);
        when(keyManagementService.decryptData(eq(keyId), eq(invalidBase64), eq(nonceB64)))
                .thenThrow(new IllegalArgumentException("Invalid Base64"));

        // When & Then
        mockMvc.perform(post("/api/keys/{keyId}/decrypt", keyId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"));

        verify(keyManagementService, times(1)).decryptData(keyId, invalidBase64, nonceB64);
    }
}
