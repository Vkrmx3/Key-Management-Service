package com.keymanagement.dto;

import java.util.Set;

/**
 * Response DTO for authentication operations.
 * Contains JWT token and user information.
 */
public class AuthResponse {

    private String token;
    private String type = "Bearer";
    private String userId;
    private String username;
    private String email;
    private Set<String> roles;

    // Constructors
    public AuthResponse() {
    }

    public AuthResponse(String token, String userId, String username, String email, Set<String> roles) {
        this.token = token;
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    // Getters and Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}
