package com.keymanagement.entity;

/**
 * User roles for role-based access control (RBAC).
 * 
 * USER: Regular user - can create keys and encrypt/decrypt with their own keys
 * ADMIN: Administrator - can manage all keys and users
 */
public enum Role {
    USER,
    ADMIN
}
