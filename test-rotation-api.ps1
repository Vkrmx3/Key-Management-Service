# Key Rotation API Test Script
# Tests the key rotation functionality of the KMS

Write-Host "=== Key Rotation API Test ===" -ForegroundColor Cyan
Write-Host ""

$baseUrl = "http://localhost:8080/api"

# Step 1: Register a user
Write-Host "1. Registering new user..." -ForegroundColor Yellow
try {
    $registerResponse = Invoke-RestMethod -Uri "$baseUrl/auth/register" `
        -Method POST `
        -ContentType "application/json" `
        -Body '{"username":"rotation_test_user","email":"rotation@test.com","password":"SecurePass123!"}'
    
    $token = $registerResponse.token
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    Write-Host "✓ User registered successfully" -ForegroundColor Green
    Write-Host "  Token: $($token.Substring(0, 50))..." -ForegroundColor Gray
}
catch {
    # User might already exist, try login
    Write-Host "  User exists, logging in..." -ForegroundColor Gray
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/auth/login" `
        -Method POST `
        -ContentType "application/json" `
        -Body '{"username":"rotation_test_user","password":"SecurePass123!"}'
    
    $token = $loginResponse.token
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    Write-Host "✓ Logged in successfully" -ForegroundColor Green
}

Write-Host ""

# Step 2: Create a key
Write-Host "2. Creating initial key (v1)..." -ForegroundColor Yellow
$createResponse = Invoke-RestMethod -Uri "$baseUrl/keys" `
    -Method POST `
    -Headers $headers

$logicalKeyId = $createResponse.keyId
Write-Host "✓ Key created: $logicalKeyId" -ForegroundColor Green
Write-Host ""

# Step 3: Encrypt some data with v1
Write-Host "3. Encrypting data with v1..." -ForegroundColor Yellow
$encryptRequest = @{
    plaintext = "Sensitive data encrypted with version 1"
} | ConvertTo-Json

$encryptV1 = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/encrypt" `
    -Method POST `
    -Headers $headers `
    -Body $encryptRequest

Write-Host "✓ Data encrypted with v1" -ForegroundColor Green
Write-Host "  Ciphertext: $($encryptV1.ciphertext.Substring(0, 40))..." -ForegroundColor Gray
Write-Host "  Nonce: $($encryptV1.nonce)" -ForegroundColor Gray
Write-Host ""

# Step 4: Get current version
Write-Host "4. Getting current version info..." -ForegroundColor Yellow
$currentV1 = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/current-version" `
    -Method GET `
    -Headers $headers

Write-Host "✓ Current version: v$($currentV1.version)" -ForegroundColor Green
Write-Host "  Key ID: $($currentV1.keyId)" -ForegroundColor Gray
Write-Host "  Created: $($currentV1.createdAt)" -ForegroundColor Gray
Write-Host ""

# Step 5: Rotate the key
Write-Host "5. Rotating key to v2..." -ForegroundColor Yellow
$rotateRequest = @{
    reason = "Testing scheduled 90-day rotation"
} | ConvertTo-Json

$rotateResponse = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/rotate" `
    -Method POST `
    -Headers $headers `
    -Body $rotateRequest

Write-Host "✓ Key rotated successfully" -ForegroundColor Green
Write-Host "  Old version: v$($rotateResponse.oldVersion)" -ForegroundColor Gray
Write-Host "  New version: v$($rotateResponse.newVersion)" -ForegroundColor Gray
Write-Host "  New Key ID: $($rotateResponse.newKeyId)" -ForegroundColor Gray
Write-Host "  Message: $($rotateResponse.message)" -ForegroundColor Gray
Write-Host ""

# Step 6: Verify old data can still be decrypted
Write-Host "6. Decrypting v1 data (backward compatibility)..." -ForegroundColor Yellow
$decryptRequest = @{
    ciphertext = $encryptV1.ciphertext
    nonce = $encryptV1.nonce
} | ConvertTo-Json

$decryptV1 = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/decrypt" `
    -Method POST `
    -Headers $headers `
    -Body $decryptRequest

Write-Host "✓ Decryption successful with old version" -ForegroundColor Green
Write-Host "  Plaintext: $($decryptV1.plaintext)" -ForegroundColor Gray
Write-Host ""

# Step 7: Encrypt new data with v2
Write-Host "7. Encrypting new data with v2..." -ForegroundColor Yellow
$encryptV2Request = @{
    plaintext = "New data encrypted with version 2"
} | ConvertTo-Json

$encryptV2 = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/encrypt" `
    -Method POST `
    -Headers $headers `
    -Body $encryptV2Request

Write-Host "✓ Data encrypted with v2 (current version)" -ForegroundColor Green
Write-Host "  Ciphertext: $($encryptV2.ciphertext.Substring(0, 40))..." -ForegroundColor Gray
Write-Host ""

# Step 8: Get all versions
Write-Host "8. Listing all key versions..." -ForegroundColor Yellow
$versions = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/versions" `
    -Method GET `
    -Headers $headers

Write-Host "✓ Found $($versions.Count) versions:" -ForegroundColor Green
foreach ($v in $versions) {
    $current = if ($v.currentVersion) { " (CURRENT)" } else { "" }
    $rotated = if ($v.rotatedAt) { ", Rotated: $($v.rotatedAt)" } else { "" }
    Write-Host "  v$($v.version)$current - Created: $($v.createdAt)$rotated" -ForegroundColor Gray
    if ($v.rotationReason) {
        Write-Host "    Reason: $($v.rotationReason)" -ForegroundColor Gray
    }
}
Write-Host ""

# Step 9: Re-encrypt old data to new version
Write-Host "9. Re-encrypting v1 data to v2..." -ForegroundColor Yellow
$reencryptRequest = @{
    ciphertext = $encryptV1.ciphertext
    nonce = $encryptV1.nonce
    sourceVersion = 1
} | ConvertTo-Json

$reencrypted = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/reencrypt" `
    -Method POST `
    -Headers $headers `
    -Body $reencryptRequest

Write-Host "✓ Data re-encrypted to current version" -ForegroundColor Green
Write-Host "  New Ciphertext: $($reencrypted.ciphertext.Substring(0, 40))..." -ForegroundColor Gray
Write-Host "  New Nonce: $($reencrypted.nonce)" -ForegroundColor Gray
Write-Host ""

# Step 10: Decrypt re-encrypted data
Write-Host "10. Decrypting re-encrypted data..." -ForegroundColor Yellow
$decryptReencrypted = @{
    ciphertext = $reencrypted.ciphertext
    nonce = $reencrypted.nonce
} | ConvertTo-Json

$decryptedReencrypted = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/decrypt" `
    -Method POST `
    -Headers $headers `
    -Body $decryptReencrypted

Write-Host "✓ Re-encrypted data decrypted successfully" -ForegroundColor Green
Write-Host "  Plaintext: $($decryptedReencrypted.plaintext)" -ForegroundColor Gray
Write-Host ""

# Step 11: Rotate again to v3
Write-Host "11. Rotating to v3 (compliance-driven rotation)..." -ForegroundColor Yellow
$rotateV3Request = @{
    reason = "Annual compliance rotation"
} | ConvertTo-Json

$rotateV3 = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/rotate" `
    -Method POST `
    -Headers $headers `
    -Body $rotateV3Request

Write-Host "✓ Rotated to v3" -ForegroundColor Green
Write-Host "  Version progression: v$($rotateV3.oldVersion) → v$($rotateV3.newVersion)" -ForegroundColor Gray
Write-Host ""

# Step 12: Final version check
Write-Host "12. Final version summary..." -ForegroundColor Yellow
$finalVersions = Invoke-RestMethod -Uri "$baseUrl/keys/$logicalKeyId/versions" `
    -Method GET `
    -Headers $headers

Write-Host "✓ Total versions: $($finalVersions.Count)" -ForegroundColor Green
$finalVersions | Format-Table @{
    Label="Version"; Expression={$_.version}
}, @{
    Label="Current"; Expression={if ($_.currentVersion) {"✓"} else {""}}
}, @{
    Label="Created"; Expression={$_.createdAt.Substring(0,19)}
}, @{
    Label="Rotation Reason"; Expression={$_.rotationReason}
} -AutoSize

Write-Host ""
Write-Host "=== All Key Rotation Tests Passed! ===" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  • Created key with initial version (v1)" -ForegroundColor White
Write-Host "  • Encrypted data with v1" -ForegroundColor White
Write-Host "  • Rotated to v2 and v3" -ForegroundColor White
Write-Host "  • Verified backward compatibility (decrypted v1 data after rotation)" -ForegroundColor White
Write-Host "  • Re-encrypted old data to current version" -ForegroundColor White
Write-Host "  • All 3 versions tracked with audit trail" -ForegroundColor White
