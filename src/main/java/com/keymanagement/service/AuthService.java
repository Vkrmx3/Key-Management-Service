package com.keymanagement.service;

import com.keymanagement.dto.AuthResponse;
import com.keymanagement.dto.LoginRequest;
import com.keymanagement.dto.RegisterRequest;
import com.keymanagement.entity.Role;
import com.keymanagement.entity.User;
import com.keymanagement.repository.UserRepository;
import com.keymanagement.security.JwtUtil;
import com.keymanagement.security.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service for authentication and user management operations.
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthService(UserRepository userRepository,
                      PasswordEncoder passwordEncoder,
                      JwtUtil jwtUtil,
                      AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    /**
     * Register a new user.
     *
     * @param registerRequest registration details
     * @return authentication response with JWT token
     */
    @Transactional
    public AuthResponse register(RegisterRequest registerRequest) {
        logger.info("Registering new user: {}", LogSanitizer.sanitize(registerRequest.getUsername()));

        // Check if username already exists
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new IllegalArgumentException("Username already exists: " + registerRequest.getUsername());
        }

        // Check if email already exists
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new IllegalArgumentException("Email already exists: " + registerRequest.getEmail());
        }

        // Create new user
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.getRoles().add(Role.USER); // Default role

        user = userRepository.save(user);
        logger.info("User registered successfully: {}", LogSanitizer.sanitize(user.getUsername()));

        // Generate JWT token
        String token = jwtUtil.generateToken(user.getUsername());

        return createAuthResponse(user, token);
    }

    /**
     * Authenticate user and generate JWT token.
     *
     * @param loginRequest login credentials
     * @return authentication response with JWT token
     */
    @Transactional
    public AuthResponse login(LoginRequest loginRequest) {
        logger.info("User login attempt: {}", LogSanitizer.sanitize(loginRequest.getUsername()));

        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate JWT token
            String token = jwtUtil.generateToken(authentication);

            // Update last login time
            User user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new IllegalStateException("User not found after authentication"));
            
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            logger.info("User logged in successfully: {}", LogSanitizer.sanitize(user.getUsername()));

            return createAuthResponse(user, token);
        } catch (BadCredentialsException e) {
            logger.warn("Failed login attempt for user: {}", LogSanitizer.sanitize(loginRequest.getUsername()));
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    /**
     * Create authentication response from user and token.
     *
     * @param user the user
     * @param token JWT token
     * @return authentication response
     */
    private AuthResponse createAuthResponse(User user, String token) {
        Set<String> roles = user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toSet());

        return new AuthResponse(
                token,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                roles
        );
    }
}
