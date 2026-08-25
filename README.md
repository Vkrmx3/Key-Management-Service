# Key Management Service (KMS) - Learning Project

[![CI](https://github.com/username/kms/actions/workflows/ci.yml/badge.svg)](https://github.com/username/kms/actions/workflows/ci.yml)
[![Security](https://github.com/username/kms/actions/workflows/security.yml/badge.svg)](https://github.com/username/kms/actions/workflows/security.yml)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://github.com/username/kms/pkgs/container/kms)

A minimal Key Management Service implementation for learning purposes, built with Spring Boot 3.x and Java 25. This project demonstrates secure key generation, encryption, and decryption using AES-256-GCM through Java's JCA/JCE APIs, with JWT-based authentication and PostgreSQL persistence.

## Features

- **JWT Authentication**: Secure user registration and login with JSON Web Tokens
- **Role-Based Access Control**: USER and ADMIN roles with Spring Security
- **Key Generation**: Create encryption keys with multiple algorithms
- **Multi-Algorithm Support**: AES-128/192/256-GCM and ChaCha20-Poly1305
- **Key Rotation**: Version-based key rotation with backward compatibility
- **Data Encryption**: Encrypt plaintext using AEAD (authenticated encryption)
- **Data Decryption**: Decrypt ciphertext with integrity verification
- **Data Re-encryption**: Migrate data from old key versions to current versions
- **PostgreSQL Persistence**: Durable key storage with JPA/Hibernate
- **Docker Support**: Complete containerized deployment with Docker Compose
- **CI/CD Pipeline**: Automated build, test, security scanning, and deployment
- **Soft Delete**: Keys are deactivated, not deleted (audit trail)
- **Security Best Practices**: 
  - 12-byte nonces (NIST SP 800-38D recommended)
  - 128-bit authentication tags
  - BCrypt password hashing
  - No logging of sensitive data (passwords, tokens, plaintext, keys, ciphertext)
  - Base64 encoding for binary data transport

## Technology Stack

- Java 25
- Spring Boot 3.5.0
- Spring Security + JWT (jjwt 0.12.6)
- PostgreSQL 16 (with H2 for tests)
- Spring Data JPA / Hibernate
- Maven
- Docker & Docker Compose
- GitHub Actions (CI/CD)
- JUnit 5 & Mockito for testing
- Java JCA/JCE for cryptography

## Prerequisites

- JDK 25 or higher
- Maven 3.6+
- PostgreSQL 16+ (or Docker)

## Getting Started

### Option 1: Docker (Recommended for Quick Start)

The fastest way to run the KMS is using Docker:

```bash
# 1. Clone and navigate to the project
cd Key-Management-Service

# 2. Copy and configure environment variables
cp .env.docker .env
# Edit .env and set secure values for DB_PASSWORD and JWT_SECRET

# 3. Start the application and database
docker compose up -d

# 4. Verify it's running
curl http://localhost:8080/actuator/health
```

That's it! The KMS and PostgreSQL are now running. See [DOCKER.md](DOCKER.md) for complete documentation.

### Option 2: Local Development Setup

If you prefer to run locally without Docker:

#### 1. Setup PostgreSQL Database

See [POSTGRES_QUICKSTART.md](POSTGRES_QUICKSTART.md) for database setup instructions.

Quick setup with Docker:
```bash
docker run --name kms-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  -d postgres:16

# Create database and user
docker exec -it kms-postgres psql -U postgres -c "CREATE DATABASE kms_db;"
docker exec -it kms-postgres psql -U postgres -c "CREATE USER kms_user WITH PASSWORD 'kms_password';"
docker exec -it kms-postgres psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE kms_db TO kms_user;"
```

#### 2. Build the Project

```bash
mvn clean install
```

#### 3. Run the Application

```bash
mvn spring-boot:run
```

The application starts on port 8080 by default.

#### 4. Run Tests

```bash
mvn test
```

## 🐳 Docker Deployment

The KMS includes complete Docker support with multi-stage builds and Docker Compose orchestration.

### Quick Start with Docker

```bash
# Start everything (app + database)
docker compose up -d

# View logs
docker compose logs -f

# Stop everything
docker compose down
```

### Docker Features

- ✅ **Multi-stage build** - Optimized image size (~200MB)
- ✅ **Non-root user** - Runs as dedicated `kms` user
- ✅ **Health checks** - Automatic health monitoring
- ✅ **Persistent storage** - Database data survives restarts
- ✅ **Environment configuration** - Easy customization via `.env`
- ✅ **Production ready** - Proper resource limits and restart policies

### Docker Architecture

```
┌─────────────────────────────────────┐
│   Docker Host                        │
│                                      │
│  ┌────────────────┐  ┌────────────┐ │
│  │   kms-app      │  │  postgres  │ │
│  │   :8080        │◄─┤   :5432    │ │
│  │   Spring Boot  │  │ PostgreSQL │ │
│  └────────────────┘  └────────────┘ │
│         ▲                   ▲        │
│         │                   │        │
│    Port 8080          postgres-data │
│    (exposed)            (volume)    │
└─────────────────────────────────────┘
```

For complete Docker documentation, see [DOCKER.md](DOCKER.md).

## 🔐 Authentication

All key management endpoints require JWT authentication. See [AUTHENTICATION.md](AUTHENTICATION.md) for complete documentation.

### Quick Start - Register & Login

```powershell
# Register a new user
$registerResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/register" `
    -Method POST `
    -ContentType "application/json" `
    -Body '{"username":"myuser","email":"user@example.com","password":"SecurePass123!"}'

$token = $registerResponse.token

# Use the token for authenticated requests
$headers = @{ "Authorization" = "Bearer $token" }
```

## API Documentation

### Authentication Endpoints (Public)

#### Register New User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

Response (201 Created):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "type": "Bearer",
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john_doe",
  "email": "john@example.com",
  "roles": ["USER"]
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "SecurePassword123!"
}
```

### Key Management Endpoints (Require Authentication)

**All requests must include**: `Authorization: Bearer <token>`

### Base URL
```
http://localhost:8080/api/keys
```

### 1. Create Key

Creates a new encryption key with optional algorithm selection.

**Endpoint**: `POST /api/keys`

**Headers**:
```
Authorization: Bearer <your-jwt-token>
Content-Type: application/json
```

**Request Body (all fields optional)**:
```json
{
  "algorithm": "AES_256_GCM",
  "description": "Production encryption key"
}
```

**Supported Algorithms**:
- `AES_128_GCM` - Fast, secure (128-bit key)
- `AES_192_GCM` - Enhanced security (192-bit key)
- `AES_256_GCM` - Maximum security (256-bit key) **[DEFAULT]**
- `CHACHA20_POLY1305` - Modern, software-optimized (256-bit key)

**Response**: `201 Created`
```json
{
  "keyId": "550e8400-e29b-41d4-a716-446655440000",
  "algorithm": "AES-256-GCM",
  "keySize": 256
}
```

**Examples**:
```bash
# Create with default algorithm (AES-256-GCM)
curl -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{}'

# Create with AES-128-GCM
curl -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "AES_128_GCM"}'

# Create with ChaCha20-Poly1305
curl -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "CHACHA20_POLY1305", "description": "Mobile app key"}'
```

### 2. Encrypt Data

Encrypts plaintext using a specific key.

**Endpoint**: `POST /api/keys/{keyId}/encrypt`

**Headers**:
```
Authorization: Bearer <your-jwt-token>
Content-Type: application/json
```

**Request Body**:
```json
{
  "plaintext": "Hello, World!"
}
```

**Response**: `200 OK`
```json
{
  "ciphertext": "Z3JhY2VmdWxseS1lbmNyeXB0ZWQtZGF0YQ==",
  "nonce": "AQIDBAUGBwgJCgsM"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/keys/{keyId}/encrypt \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Sensitive data"}'
```

**Notes**:
- Plaintext is accepted as UTF-8 string
- Ciphertext and nonce are Base64-encoded
- A fresh 12-byte nonce is generated for each encryption
- Store both ciphertext and nonce - you need both for decryption

### 3. Decrypt Data

Decrypts ciphertext using a specific key.

**Endpoint**: `POST /api/keys/{keyId}/decrypt`

**Headers**:
```
Authorization: Bearer <your-jwt-token>
Content-Type: application/json
```

**Request Body**:
```json
{
  "ciphertext": "Z3JhY2VmdWxseS1lbmNyeXB0ZWQtZGF0YQ==",
  "nonce": "AQIDBAUGBwgJCgsM"
}
```

**Response**: `200 OK`
```json
{
  "plaintext": "Hello, World!"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/keys/{keyId}/decrypt \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "Z3JhY2VmdWxseS1lbmNyeXB0ZWQtZGF0YQ==", "nonce": "AQIDBAUGBwgJCgsM"}'
```

## 🔄 Key Rotation

The KMS supports key rotation with versioning, allowing you to rotate encryption keys while maintaining the ability to decrypt data encrypted with older versions.

### Key Rotation Endpoints

#### Rotate a Key
```http
POST /api/keys/{logicalKeyId}/rotate
Authorization: Bearer <your-jwt-token>
Content-Type: application/json

{
  "reason": "Scheduled 90-day rotation"
}
```

**Response**: `201 Created`
```json
{
  "logicalKeyId": "550e8400-e29b-41d4-a716-446655440000",
  "oldVersion": 1,
  "newVersion": 2,
  "newKeyId": "660f9511-f39c-52e5-b827-557766551111",
  "message": "Key rotated successfully"
}
```

#### Get All Key Versions
```http
GET /api/keys/{logicalKeyId}/versions
Authorization: Bearer <your-jwt-token>
```

**Response**: `200 OK`
```json
[
  {
    "keyId": "660f9511-f39c-52e5-b827-557766551111",
    "logicalKeyId": "550e8400-e29b-41d4-a716-446655440000",
    "version": 2,
    "currentVersion": true,
    "algorithm": "AES",
    "keySize": 256,
    "createdAt": "2024-01-15T10:30:00"
  },
  {
    "keyId": "550e8400-e29b-41d4-a716-446655440000",
    "logicalKeyId": "550e8400-e29b-41d4-a716-446655440000",
    "version": 1,
    "currentVersion": false,
    "algorithm": "AES",
    "keySize": 256,
    "createdAt": "2024-01-01T10:00:00",
    "rotatedAt": "2024-01-15T10:30:00",
    "rotationReason": "Scheduled 90-day rotation"
  }
]
```

#### Get Current Version
```http
GET /api/keys/{logicalKeyId}/current-version
Authorization: Bearer <your-jwt-token>
```

#### Re-encrypt Data with New Version
```http
POST /api/keys/{logicalKeyId}/reencrypt
Authorization: Bearer <your-jwt-token>
Content-Type: application/json

{
  "ciphertext": "old-encrypted-data",
  "nonce": "old-nonce",
  "sourceVersion": 1
}
```

**Response**: `200 OK`
```json
{
  "ciphertext": "newly-encrypted-data",
  "nonce": "new-nonce"
}
```

### Key Rotation Concepts

- **Logical Key ID**: Stable identifier that doesn't change across rotations
- **Physical Key ID**: Unique ID for each key version
- **Version Number**: Starts at 1, increments with each rotation
- **Current Version**: Only one version is marked as current (used for new encryptions)

### How It Works

1. **Encryption**: Always uses the current version of a key
2. **Decryption**: Works with any version of the key
3. **Rotation**: Creates a new version, marks old version as non-current
4. **Re-encryption**: Migrates data from old version to current version

For complete documentation, see [KEY_ROTATION.md](KEY_ROTATION.md).

## Error Responses

All errors follow a consistent format:

```json
{
  "timestamp": "2026-08-25T10:30:00",
  "status": 404,
  "error": "Not Found",
  "message": "Key not found: invalid-key-id",
  "path": "/api/keys/invalid-key-id/encrypt"
}
```

### Common Error Codes

- **400 Bad Request**: Invalid input, validation failure, decryption failure, or duplicate username/email
- **401 Unauthorized**: Missing or invalid JWT token, wrong username/password
- **404 Not Found**: Key ID or user does not exist
- **500 Internal Server Error**: Unexpected server error

## Complete Usage Example (With Authentication)

### PowerShell
```powershell
# 1. Register a new user
$registerResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/register" `
    -Method POST `
    -ContentType "application/json" `
    -Body '{"username":"demouser","email":"demo@example.com","password":"SecurePass123!"}'

$token = $registerResponse.token
$headers = @{ "Authorization" = "Bearer $token" }
Write-Host "JWT Token: $($token.Substring(0, 50))..."

# 2. Create a new key
$keyResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/keys" `
    -Method POST `
    -Headers $headers `
    -ContentType "application/json" `
    -Body '{}'
$keyId = $keyResponse.keyId
Write-Host "Created key: $keyId"

# 3. Encrypt data
$encryptResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/keys/$keyId/encrypt" `
    -Method POST `
    -Headers $headers `
    -ContentType "application/json" `
    -Body '{"plaintext":"My secret message"}'
$ciphertext = $encryptResponse.ciphertext
$nonce = $encryptResponse.nonce
Write-Host "Encrypted data: $ciphertext"

# 4. Decrypt data
$decryptBody = @{ ciphertext = $ciphertext; nonce = $nonce } | ConvertTo-Json
$decryptResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/keys/$keyId/decrypt" `
    -Method POST `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $decryptBody
Write-Host "Decrypted: $($decryptResponse.plaintext)"
```

### Bash / curl
```bash
# 1. Register and get token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"demouser","email":"demo@example.com","password":"SecurePass123!"}' \
  | jq -r '.token')
echo "Token: ${TOKEN:0:50}..."

# 2. Create a new key
KEY_ID=$(curl -s -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  | jq -r '.keyId')
echo "Created key: $KEY_ID"

# 3. Encrypt data
ENCRYPT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/keys/$KEY_ID/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "My secret message"}')
CIPHERTEXT=$(echo $ENCRYPT_RESPONSE | jq -r '.ciphertext')
NONCE=$(echo $ENCRYPT_RESPONSE | jq -r '.nonce')
echo "Encrypted data: $CIPHERTEXT"

# 4. Decrypt data
curl -s -X POST http://localhost:8080/api/keys/$KEY_ID/decrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext\": \"$CIPHERTEXT\", \"nonce\": \"$NONCE\"}" \
  | jq
```

## Testing

### Run Unit and Integration Tests
```bash
mvn test
```

### Test Authentication API
```powershell
.\test-auth-api.ps1
```

This script tests:
- User registration
- Duplicate username validation
- User login
- Wrong password validation
- Authenticated key operations
- Invalid token handling

## Project Structure

```
src/
├── main/
│   ├── java/com/keymanagement/
│   │   ├── KmsApplication.java              # Spring Boot main class
│   │   ├── controller/
│   │   │   ├── KeyManagementController.java # REST endpoints
│   │   │   ├── KeyRotationController.java   # Key rotation endpoints
│   │   │   └── AuthController.java          # Authentication endpoints
│   │   ├── service/
│   │   │   ├── CryptoService.java           # AES-256-GCM operations
│   │   │   ├── KeyStorageService.java       # PostgreSQL key persistence
│   │   │   ├── KeyManagementService.java    # Business logic orchestration
│   │   │   ├── KeyRotationService.java      # Key rotation & versioning
│   │   │   └── AuthService.java             # Authentication logic
│   │   ├── security/
│   │   │   ├── JwtUtil.java                 # JWT token operations
│   │   │   ├── JwtAuthenticationFilter.java # JWT filter
│   │   │   ├── UserPrincipal.java           # UserDetails implementation
│   │   │   └── CustomUserDetailsService.java # User loading service
│   │   ├── config/
│   │   │   └── SecurityConfig.java          # Spring Security configuration
│   │   ├── entity/
│   │   │   ├── KeyEntity.java  demonstrating production-ready security patterns**

**Implemented Security**:
- ✅ AES-256-GCM authenticated encryption
- ✅ Fresh nonces for every encryption
- ✅ No logging of sensitive data
- ✅ Proper exception handling without leaking crypto details
- ✅ JWT-based authentication with BCrypt password hashing
- ✅ PostgreSQL persistence with transaction safety
- ✅ Key rotation with versioning
- ✅ Environment variable configuration for secrets
- ✅ Role-based access control (RBAC)
- ✅ Audit trail with soft deletes

**NOT Implemented (out of scope for learning project)**:
- ❌ Rate limiting
- ❌ HSM integration
- ❌ Envelope encryption
- ❌ Multi-tenancy
- ❌ Advanced audit logging (e.g., full request/response logging)
- ❌ Key expiration policies
- ❌ Automated rotation schedules
⚠️ **This is a learning project, NOT production-ready**

**Implemented Security**:
- ✅ AES-256-GCM authenticated encryption
- ✅ Fresh nonces for every encryption
- ✅ No logging of sensitive data
- ✅ Proper exception handling without leaking crypto details

**NOT Implemented (out of scope)**:
- ❌ Persistent storage (keys lost on restart)
- ❌ Authentication/authorization
- ❌ Key rotation or versioning
- ❌ Audit logging
- ❌ Rate limiting
- ❌ HSM integration
- ❌ Envelope encryption
- ❌ Multi-tenancy

## Learning Objectives

This project demonstrates:
1. **Java Cryptography Architecture (JCA/JCE)**: Using built-in Java crypto APIs
2. **AES-256-GCM**: Modern authenticated encryption mode
8. **JWT Authentication**: Token-based authentication with Spring Security
9. **Database Persistence**: JPA/Hibernate with PostgreSQL
10. **Key Rotation**: Implementing key versioning and rotation strategies
11. **Environment Configuration**: Using environment variables for secrets
12. **RBAC**: Role-based access control implementation

## 🔄 CI/CD Pipeline

The KMS includes a comprehensive CI/CD pipeline with GitHub Actions:

### Automated Workflows

- **CI (Continuous Integration)**
  - ✅ Build and compile on every push/PR
  - ✅ Run unit and integration tests
  - ✅ Generate code coverage reports
  - ✅ Code quality analysis (SonarCloud)
  - ✅ Docker image build and test

- **Security Scanning**
  - ✅ OWASP dependency vulnerability checks
  - ✅ Trivy container image scanning
  - ✅ CodeQL static security analysis
  - ✅ Secret scanning (TruffleHog, GitLeaks)
  - ✅ Dockerfile best practices (Hadolint)
  - ✅ SBOM generation

- **CD (Continuous Deployment)**
  - ✅ Build and push Docker images to GHCR
  - ✅ Multi-platform images (amd64, arm64)
  - ✅ Automated staging deployment
  - ✅ Production deployment with approval
  - ✅ Automatic rollback on failure

### Quick Start

```bash
# Push to main triggers full pipeline
git push origin main

# Tag for production release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

For complete CI/CD documentation, see [CICD.md](CICD.md).

## Documentation

- [CICD.md](CICD.md) - Complete CI/CD pipeline guide
- [DOCKER.md](DOCKER.md) - Complete Docker deployment guide
- [KEY_ROTATION.md](KEY_ROTATION.md) - Complete guide to key rotation
- [MULTI_ALGORITHM.md](MULTI_ALGORITHM.md) - Multi-algorithm support guide
- [AUTHENTICATION.md](AUTHENTICATION.md) - JWT authentication documentation
- [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md) - Configuration guide
- [PERSISTENCE_TESTS.md](PERSISTENCE_TESTS.md) - Database testing guide
3. **Nonce Management**: Generating and using unique nonces per encryption
4. **RESTful API Design**: Clean API structure with Spring Boot
5. **Testing**: Unit tests and integration tests with MockMvc
6. **Error Handling**: Proper exception handling and user-friendly error messages
7. **Security Mindset**: Not logging sensitive data, using secure random, proper encoding

## License

This project is licensed under the terms specified in the LICENSE file.
