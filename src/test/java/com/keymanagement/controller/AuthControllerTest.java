package com.keymanagement.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keymanagement.dto.AuthResponse;
import com.keymanagement.dto.LoginRequest;
import com.keymanagement.dto.RegisterRequest;
import com.keymanagement.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for AuthController.
 */
@WebMvcTest(AuthController.class)
@Import(TestSecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @Test
    void testRegister_ShouldReturnAuthResponse() throws Exception {
        // Given
        RegisterRequest registerRequest = new RegisterRequest("john_doe", "john@example.com", "Password123!");
        AuthResponse authResponse = new AuthResponse(
                "mock.jwt.token",
                "user-id-123",
                "john_doe",
                "john@example.com",
                Set.of("USER")
        );

        when(authService.register(any(RegisterRequest.class))).thenReturn(authResponse);

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").value("mock.jwt.token"))
                .andExpect(jsonPath("$.userId").value("user-id-123"))
                .andExpect(jsonPath("$.username").value("john_doe"))
                .andExpect(jsonPath("$.email").value("john@example.com"))
                .andExpect(jsonPath("$.roles[0]").value("USER"));

        verify(authService, times(1)).register(any(RegisterRequest.class));
    }

    @Test
    void testRegister_WithInvalidData_ShouldReturnBadRequest() throws Exception {
        // Given - missing required fields
        RegisterRequest invalidRequest = new RegisterRequest("", "", "");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());

        verify(authService, never()).register(any(RegisterRequest.class));
    }

    @Test
    void testRegister_WithShortPassword_ShouldReturnBadRequest() throws Exception {
        // Given - password too short
        RegisterRequest invalidRequest = new RegisterRequest("john_doe", "john@example.com", "Pass1");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());

        verify(authService, never()).register(any(RegisterRequest.class));
    }

    @Test
    void testRegister_WithDuplicateUsername_ShouldReturnBadRequest() throws Exception {
        // Given
        RegisterRequest registerRequest = new RegisterRequest("existing_user", "new@example.com", "Password123!");
        
        when(authService.register(any(RegisterRequest.class)))
                .thenThrow(new IllegalArgumentException("Username already exists: existing_user"));

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Username already exists: existing_user"));

        verify(authService, times(1)).register(any(RegisterRequest.class));
    }

    @Test
    void testLogin_ShouldReturnAuthResponse() throws Exception {
        // Given
        LoginRequest loginRequest = new LoginRequest("john_doe", "Password123!");
        AuthResponse authResponse = new AuthResponse(
                "mock.jwt.token",
                "user-id-123",
                "john_doe",
                "john@example.com",
                Set.of("USER")
        );

        when(authService.login(any(LoginRequest.class))).thenReturn(authResponse);

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mock.jwt.token"))
                .andExpect(jsonPath("$.userId").value("user-id-123"))
                .andExpect(jsonPath("$.username").value("john_doe"));

        verify(authService, times(1)).login(any(LoginRequest.class));
    }

    @Test
    void testLogin_WithInvalidCredentials_ShouldReturnUnauthorized() throws Exception {
        // Given
        LoginRequest loginRequest = new LoginRequest("john_doe", "WrongPassword");
        
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new BadCredentialsException("Invalid username or password"));

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid username or password"));

        verify(authService, times(1)).login(any(LoginRequest.class));
    }

    @Test
    void testLogin_WithMissingFields_ShouldReturnBadRequest() throws Exception {
        // Given - missing required fields
        LoginRequest invalidRequest = new LoginRequest("", "");

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());

        verify(authService, never()).login(any(LoginRequest.class));
    }
}
