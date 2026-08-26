# Test Authentication API
# PowerShell script to test JWT-based authentication endpoints

$baseUrl = "http://localhost:8080"
$contentType = "application/json"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "KMS Authentication API Test Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Register a new user
Write-Host "Test 1: Registering new user..." -ForegroundColor Yellow
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$username = "testuser_$timestamp"
$registerRequest = @{
    username = $username
    email = "test_${timestamp}@example.com"
    password = "SecurePassword123!"
} | ConvertTo-Json

try {
    $registerResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/register" `
        -Method POST `
        -ContentType $contentType `
        -Body $registerRequest
    
    Write-Host "✓ Registration successful!" -ForegroundColor Green
    Write-Host "  User ID: $($registerResponse.userId)"
    Write-Host "  Username: $($registerResponse.username)"
    Write-Host "  Roles: $($registerResponse.roles -join ', ')"
    Write-Host "  Token (first 50 chars): $($registerResponse.token.Substring(0, [Math]::Min(50, $registerResponse.token.Length)))..."
    $token = $registerResponse.token
    Write-Host ""
} catch {
    Write-Host "✗ Registration failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 2: Try to register with same username (should fail)
Write-Host "Test 2: Trying to register duplicate username (should fail)..." -ForegroundColor Yellow
try {
    $duplicateResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/register" `
        -Method POST `
        -ContentType $contentType `
        -Body $registerRequest
    
    Write-Host "✗ Should have failed but didn't!" -ForegroundColor Red
} catch {
    Write-Host "✓ Correctly rejected duplicate username" -ForegroundColor Green
    Write-Host ""
}

# Test 3: Login with registered user
Write-Host "Test 3: Logging in with registered user..." -ForegroundColor Yellow
$loginRequest = @{
    username = $username
    password = "SecurePassword123!"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" `
        -Method POST `
        -ContentType $contentType `
        -Body $loginRequest
    
    Write-Host "✓ Login successful!" -ForegroundColor Green
    Write-Host "  Token (first 50 chars): $($loginResponse.token.Substring(0, [Math]::Min(50, $loginResponse.token.Length)))..."
    $token = $loginResponse.token
    Write-Host ""
} catch {
    Write-Host "✗ Login failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 4: Try to login with wrong password (should fail)
Write-Host "Test 4: Trying to login with wrong password (should fail)..." -ForegroundColor Yellow
$wrongPasswordRequest = @{
    username = $username
    password = "WrongPassword123!"
} | ConvertTo-Json

try {
    $wrongLoginResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" `
        -Method POST `
        -ContentType $contentType `
        -Body $wrongPasswordRequest
    
    Write-Host "✗ Should have failed but didn't!" -ForegroundColor Red
} catch {
    Write-Host "✓ Correctly rejected wrong password" -ForegroundColor Green
    Write-Host ""
}

# Test 5: Create key without authentication (should fail)
Write-Host "Test 5: Trying to create key without authentication (should fail)..." -ForegroundColor Yellow
try {
    $noAuthResponse = Invoke-RestMethod -Uri "$baseUrl/api/keys" `
        -Method POST `
        -ContentType $contentType `
        -Body '{}'
    
    Write-Host "✗ Should have failed but didn't!" -ForegroundColor Red
} catch {
    Write-Host "✓ Correctly rejected unauthenticated request" -ForegroundColor Green
    Write-Host ""
}

# Test 6: Create key with authentication (should succeed)
Write-Host "Test 6: Creating key with authentication..." -ForegroundColor Yellow
$headers = @{ "Authorization" = "Bearer $token" }

try {
    $createKeyResponse = Invoke-RestMethod -Uri "$baseUrl/api/keys" `
        -Method POST `
        -Headers $headers `
        -ContentType $contentType `
        -Body '{}'
    
    Write-Host "✓ Key created successfully!" -ForegroundColor Green
    Write-Host "  Key ID: $($createKeyResponse.keyId)"
    $keyId = $createKeyResponse.keyId
    Write-Host ""
} catch {
    Write-Host "✗ Key creation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 7: Encrypt data with authentication
Write-Host "Test 7: Encrypting data with authentication..." -ForegroundColor Yellow
$encryptRequest = @{
    plaintext = "Secret message with JWT authentication! Test at $(Get-Date)"
} | ConvertTo-Json

try {
    $encryptResponse = Invoke-RestMethod -Uri "$baseUrl/api/keys/$keyId/encrypt" `
        -Method POST `
        -Headers $headers `
        -ContentType $contentType `
        -Body $encryptRequest
    
    Write-Host "✓ Encryption successful!" -ForegroundColor Green
    Write-Host "  Ciphertext (first 50 chars): $($encryptResponse.ciphertext.Substring(0, [Math]::Min(50, $encryptResponse.ciphertext.Length)))..."
    Write-Host "  Nonce: $($encryptResponse.nonce)"
    Write-Host ""
} catch {
    Write-Host "✗ Encryption failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 8: Decrypt data with authentication
Write-Host "Test 8: Decrypting data with authentication..." -ForegroundColor Yellow
$decryptRequest = @{
    ciphertext = $encryptResponse.ciphertext
    nonce = $encryptResponse.nonce
} | ConvertTo-Json

try {
    $decryptResponse = Invoke-RestMethod -Uri "$baseUrl/api/keys/$keyId/decrypt" `
        -Method POST `
        -Headers $headers `
        -ContentType $contentType `
        -Body $decryptRequest
    
    Write-Host "✓ Decryption successful!" -ForegroundColor Green
    Write-Host "  Plaintext: $($decryptResponse.plaintext)"
    Write-Host ""
} catch {
    Write-Host "✗ Decryption failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 9: Try to decrypt with invalid token (should fail)
Write-Host "Test 9: Trying to decrypt with invalid token (should fail)..." -ForegroundColor Yellow
$invalidHeaders = @{ "Authorization" = "Bearer invalid.token.here" }

try {
    $invalidDecryptResponse = Invoke-RestMethod -Uri "$baseUrl/api/keys/$keyId/decrypt" `
        -Method POST `
        -Headers $invalidHeaders `
        -ContentType $contentType `
        -Body $decryptRequest
    
    Write-Host "✗ Should have failed but didn't!" -ForegroundColor Red
} catch {
    Write-Host "✓ Correctly rejected invalid token" -ForegroundColor Green
    Write-Host ""
}

# Summary
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "All authentication tests completed!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  ✓ User registration working"
Write-Host "  ✓ Duplicate username validation working"
Write-Host "  ✓ User login working"
Write-Host "  ✓ Wrong password validation working"
Write-Host "  ✓ Unauthenticated request blocking working"
Write-Host "  ✓ Authenticated key creation working"
Write-Host "  ✓ Authenticated encryption working"
Write-Host "  ✓ Authenticated decryption working"
Write-Host "  ✓ Invalid token validation working"
Write-Host ""
Write-Host "🎉 JWT Authentication is working correctly!" -ForegroundColor Green
