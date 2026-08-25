-- Database Setup Script for PostgreSQL
-- Run this script to create the database and user for KMS

-- Create database
CREATE DATABASE kms_db;

-- Create user
CREATE USER kms_user WITH ENCRYPTED PASSWORD 'kms_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE kms_db TO kms_user;

-- Connect to kms_db and grant schema privileges
\c kms_db
GRANT ALL ON SCHEMA public TO kms_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO kms_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO kms_user;

-- Table will be created automatically by Hibernate based on @Entity classes
-- But here's the schema for reference:
/*
CREATE TABLE encryption_keys (
    key_id VARCHAR(36) PRIMARY KEY,
    key_material BYTEA NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    key_size INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description VARCHAR(500),
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_encryption_keys_active ON encryption_keys(active);
CREATE INDEX idx_encryption_keys_created_at ON encryption_keys(created_at);
*/
