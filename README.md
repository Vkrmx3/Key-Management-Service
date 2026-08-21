# Key Management Service (KMS) - Learning Project

A minimal Key Management Service implementation for learning purposes, built with Spring Boot 3.x and Java 21. This project demonstrates secure key generation, encryption, and decryption using AES-256-GCM through Java's JCA/JCE APIs.

## Features

- **Key Generation**: Create AES-256 encryption keys
- **Data Encryption**: Encrypt plaintext using AES-256-GCM with fresh nonces
- **Data Decryption**: Decrypt ciphertext with authenticated encryption
- **In-Memory Storage**: Simple thread-safe key storage (for learning)
- **Security Best Practices**: 
  - 12-byte nonces (NIST SP 800-38D recommended)
  - 128-bit authentication tags
  - No logging of sensitive data (plaintext, keys, ciphertext)
  - Base64 encoding for binary data transport

## Technology Stack

- Java 21
- Spring Boot 3.4.0
- Maven
- JUnit 5 & Mockito for testing
- Java JCA/JCE for cryptography

## Prerequisites

- JDK 21 or higher
- Maven 3.6+

## Getting Started

### Build the Project

```bash
mvn clean install
```

### Run the Application

```bash
mvn spring-boot:run
```

The application starts on port 8080 by default.

### Run Tests

```bash
mvn test
```

## API Documentation

### Base URL
```
http://localhost:8080/api/keys
```

### 1. Create Key

Creates a new AES-256 encryption key.

**Endpoint**: `POST /api/keys`

**Request Body**: Empty or `{}`

**Response**: `201 Created`
```json
{
  "keyId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/keys \
  -H "Content-Type: application/json" \
  -d '{}'
```

### 2. Encrypt Data

Encrypts plaintext using a specific key.

**Endpoint**: `POST /api/keys/{keyId}/encrypt`

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
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "Z3JhY2VmdWxseS1lbmNyeXB0ZWQtZGF0YQ==", "nonce": "AQIDBAUGBwgJCgsM"}'
```

## Error Responses

All errors follow a consistent format:

```json
{
  "timestamp": "2026-08-21T10:30:00",
  "status": 404,
  "error": "Not Found",
  "message": "Key not found: invalid-key-id",
  "path": "/api/keys/invalid-key-id/encrypt"
}
```

### Common Error Codes

- **400 Bad Request**: Invalid input, validation failure, or decryption failure
- **404 Not Found**: Key ID does not exist
- **500 Internal Server Error**: Unexpected server error

## Complete Usage Example

```bash
# 1. Create a new key
KEY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/keys \
  -H "Content-Type: application/json" \
  -d '{}')
KEY_ID=$(echo $KEY_RESPONSE | jq -r '.keyId')
echo "Created key: $KEY_ID"

# 2. Encrypt data
ENCRYPT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/keys/$KEY_ID/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "My secret message"}')
CIPHERTEXT=$(echo $ENCRYPT_RESPONSE | jq -r '.ciphertext')
NONCE=$(echo $ENCRYPT_RESPONSE | jq -r '.nonce')
echo "Encrypted data: $CIPHERTEXT"

# 3. Decrypt data
curl -X POST http://localhost:8080/api/keys/$KEY_ID/decrypt \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext\": \"$CIPHERTEXT\", \"nonce\": \"$NONCE\"}"
```

## Project Structure

```
src/
├── main/
│   ├── java/com/keymanagement/
│   │   ├── KmsApplication.java              # Spring Boot main class
│   │   ├── controller/
│   │   │   └── KeyManagementController.java # REST endpoints
│   │   ├── service/
│   │   │   ├── CryptoService.java           # AES-256-GCM operations
│   │   │   ├── KeyStorageService.java       # In-memory key storage
│   │   │   └── KeyManagementService.java    # Business logic orchestration
│   │   ├── dto/                             # Request/response models
│   │   ├── model/
│   │   │   └── EncryptedData.java           # Domain model
│   │   └── exception/                       # Custom exceptions & handler
│   └── resources/
│       └── application.properties           # Configuration
└── test/
    └── java/com/keymanagement/              # Unit & integration tests
```

## Security Considerations

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
3. **Nonce Management**: Generating and using unique nonces per encryption
4. **RESTful API Design**: Clean API structure with Spring Boot
5. **Testing**: Unit tests and integration tests with MockMvc
6. **Error Handling**: Proper exception handling and user-friendly error messages
7. **Security Mindset**: Not logging sensitive data, using secure random, proper encoding

## License

This project is licensed under the terms specified in the LICENSE file.
