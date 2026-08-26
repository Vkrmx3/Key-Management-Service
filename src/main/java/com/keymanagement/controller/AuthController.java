package com.keymanagement.controller;

import com.keymanagement.dto.AuthResponse;
import com.keymanagement.dto.LoginRequest;
import com.keymanagement.dto.RegisterRequest;
import com.keymanagement.service.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.regex.Pattern;

/**
 * REST controller for authentication endpoints.
 * Handles user registration and login.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final Pattern CRLF_PATTERN = Pattern.compile("[\\r\\n]");

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Register a new user.
     *
     * @param registerRequest registration details
     * @return authentication response with JWT token
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        String sanitizedUsername = sanitizeForLogging(registerRequest.getUsername());
        logger.info("Registration request received for username: {}", sanitizedUsername);
        
        AuthResponse response = authService.register(registerRequest);
        
        logger.info("User registered successfully: {}", sanitizedUsername);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Login user and generate JWT token.
     *
     * @param loginRequest login credentials
     * @return authentication response with JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        String sanitizedUsername = sanitizeForLogging(loginRequest.getUsername());
        logger.info("Login request received for username: {}", sanitizedUsername);
        
        AuthResponse response = authService.login(loginRequest);
        
        logger.info("User logged in successfully: {}", sanitizedUsername);
        return ResponseEntity.ok(response);
    }

    /**
     * Sanitize user input for logging to prevent log injection attacks.
     * Removes CR/LF characters that could be used for log forging.
     *
     * @param input user-provided string
     * @return sanitized string safe for logging
     */
    private String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        return CRLF_PATTERN.matcher(input).replaceAll("_");
    }
}
