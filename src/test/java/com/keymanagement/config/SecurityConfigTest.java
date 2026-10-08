package com.keymanagement.config;

import com.keymanagement.controller.AuthController;
import com.keymanagement.controller.KeyManagementController;
import com.keymanagement.dto.AuthResponse;
import com.keymanagement.dto.LoginRequest;
import com.keymanagement.dto.RegisterRequest;
import com.keymanagement.security.CustomUserDetailsService;
import com.keymanagement.security.JwtUtil;
import com.keymanagement.service.AuthService;
import com.keymanagement.service.KeyManagementService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest({AuthController.class, KeyManagementController.class})
@Import(SecurityConfig.class)
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private KeyManagementService keyManagementService;

    @MockitoBean
    private JwtUtil jwtUtil;

    @MockitoBean
    private CustomUserDetailsService userDetailsService;

    @Test
    void testKeyCreation_WithBearerToken_ShouldNotRequireCsrfToken() throws Exception {
        mockValidBearerToken();
        when(keyManagementService.createKey()).thenReturn("key-id");

        mockMvc.perform(post("/api/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").value("key-id"))
                .andExpect(result -> assertNull(result.getRequest().getSession(false)));

        verify(keyManagementService).createKey();
    }

    @Test
    void testKeyCreation_WithInvalidBearerToken_ShouldRejectRequest() throws Exception {
        mockMvc.perform(post("/api/keys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token"))
                .andExpect(status().isForbidden());

        verifyNoInteractions(keyManagementService);
    }

    @Test
    void testKeyCreation_WithoutCsrfToken_ShouldRejectNonBearerAuthentication() throws Exception {
        mockMvc.perform(post("/api/keys").with(user("testuser")))
                .andExpect(status().isForbidden());

        verifyNoInteractions(keyManagementService);
    }

    @Test
    void testKeyCreation_WithInvalidCsrfToken_ShouldRejectNonBearerAuthentication() throws Exception {
        mockMvc.perform(post("/api/keys").with(user("testuser")).with(csrf().useInvalidToken()))
                .andExpect(status().isForbidden());

        verifyNoInteractions(keyManagementService);
    }

    @Test
    void testKeyCreation_WithCsrfToken_ShouldAllowNonBearerAuthentication() throws Exception {
        when(keyManagementService.createKey()).thenReturn("key-id");

        mockMvc.perform(post("/api/keys").with(user("testuser")).with(csrf()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").value("key-id"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearer ", "Basic credentials", "Bearer\tvalid-token"})
    void testKeyCreation_WithOtherAuthorizationHeaders_ShouldStillRequireCsrfToken(String authorization) throws Exception {
        mockMvc.perform(post("/api/keys").with(user("testuser"))
                        .header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(status().isForbidden());

        verifyNoInteractions(keyManagementService);
    }

    @Test
    void testBearerHeader_OutsideKeyApi_ShouldNotDisableCsrf() throws Exception {
        mockValidBearerToken();

        mockMvc.perform(post("/browser-action")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token"))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/json", "application/json;charset=UTF-8", "application/vnd.kms+json"})
    void testJsonLogin_ShouldNotRequireCsrfToken(String contentType) throws Exception {
        when(authService.login(any(LoginRequest.class))).thenReturn(
                new AuthResponse("test-token", "user-id", "testuser", "test@example.com", Set.of("USER")));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(contentType)
                        .content("{\"username\":\"testuser\",\"password\":\"Password123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("test-token"))
                .andExpect(result -> assertNull(result.getRequest().getSession(false)));
    }

    @Test
    void testJsonRegistration_ShouldNotRequireCsrfToken() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenReturn(
                new AuthResponse("test-token", "user-id", "testuser", "test@example.com", Set.of("USER")));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"testuser\",\"email\":\"test@example.com\",\"password\":\"Password123!\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").value("test-token"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/auth/login", "/api/auth/register"})
    void testFormAuthentication_WithoutCsrfToken_ShouldRejectRequest(String endpoint) throws Exception {
        mockMvc.perform(post(endpoint)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", "testuser")
                        .param("password", "Password123!"))
                .andExpect(status().isForbidden());

        verifyNoInteractions(authService);
    }

    private void mockValidBearerToken() {
        when(jwtUtil.validateToken("valid-token")).thenReturn(true);
        when(jwtUtil.getUsernameFromToken("valid-token")).thenReturn("testuser");
        when(userDetailsService.loadUserByUsername("testuser"))
                .thenReturn(User.withUsername("testuser").password("unused").roles("USER").build());
    }
}