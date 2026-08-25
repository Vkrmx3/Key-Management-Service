# Quick Docker Test Script
# Validates Docker setup without full deployment

Write-Host "=== Docker Setup Validation ===" -ForegroundColor Cyan
Write-Host ""

# Check Docker installation
Write-Host "1. Checking Docker installation..." -ForegroundColor Yellow
try {
    $dockerVersion = docker --version
    Write-Host "✓ Docker installed: $dockerVersion" -ForegroundColor Green
}
catch {
    Write-Host "✗ Docker not found! Please install Docker Desktop." -ForegroundColor Red
    exit 1
}

# Check Docker Compose
Write-Host ""
Write-Host "2. Checking Docker Compose..." -ForegroundColor Yellow
try {
    $composeVersion = docker compose version
    Write-Host "✓ Docker Compose available: $composeVersion" -ForegroundColor Green
}
catch {
    Write-Host "✗ Docker Compose not found!" -ForegroundColor Red
    exit 1
}

# Check if Docker is running
Write-Host ""
Write-Host "3. Checking Docker daemon..." -ForegroundColor Yellow
try {
    docker ps | Out-Null
    Write-Host "✓ Docker daemon is running" -ForegroundColor Green
}
catch {
    Write-Host "✗ Docker daemon not running! Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Validate Dockerfile
Write-Host ""
Write-Host "4. Validating Dockerfile..." -ForegroundColor Yellow
if (Test-Path "Dockerfile") {
    Write-Host "✓ Dockerfile found" -ForegroundColor Green
    
    # Check for multi-stage build
    $dockerfileContent = Get-Content "Dockerfile" -Raw
    if ($dockerfileContent -match "FROM.*AS build") {
        Write-Host "  ✓ Multi-stage build configured" -ForegroundColor Gray
    }
    if ($dockerfileContent -match "USER kms") {
        Write-Host "  ✓ Non-root user configured" -ForegroundColor Gray
    }
    if ($dockerfileContent -match "HEALTHCHECK") {
        Write-Host "  ✓ Health check configured" -ForegroundColor Gray
    }
}
else {
    Write-Host "✗ Dockerfile not found!" -ForegroundColor Red
    exit 1
}

# Validate docker-compose.yml
Write-Host ""
Write-Host "5. Validating docker-compose.yml..." -ForegroundColor Yellow
if (Test-Path "docker-compose.yml") {
    Write-Host "✓ docker-compose.yml found" -ForegroundColor Green
    
    # Validate syntax
    try {
        docker compose config | Out-Null
        Write-Host "  ✓ Syntax is valid" -ForegroundColor Gray
    }
    catch {
        Write-Host "  ✗ Syntax error in docker-compose.yml" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "✗ docker-compose.yml not found!" -ForegroundColor Red
    exit 1
}

# Check for .env file
Write-Host ""
Write-Host "6. Checking environment configuration..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host "✓ .env file exists" -ForegroundColor Green
}
elseif (Test-Path ".env.docker") {
    Write-Host "⚠ .env.docker found but .env missing" -ForegroundColor Yellow
    Write-Host "  Run: cp .env.docker .env" -ForegroundColor Gray
}
else {
    Write-Host "⚠ No environment file found (will use defaults)" -ForegroundColor Yellow
}

# Check for port conflicts
Write-Host ""
Write-Host "7. Checking for port conflicts..." -ForegroundColor Yellow
$portsToCheck = @(8080, 5432)
$conflicts = @()

foreach ($port in $portsToCheck) {
    $inUse = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($inUse) {
        $conflicts += $port
        Write-Host "  ⚠ Port $port is already in use" -ForegroundColor Yellow
    }
    else {
        Write-Host "  ✓ Port $port is available" -ForegroundColor Gray
    }
}

if ($conflicts.Count -gt 0) {
    Write-Host "⚠ Port conflicts detected. Stop services or modify docker-compose.yml" -ForegroundColor Yellow
}
else {
    Write-Host "✓ All required ports are available" -ForegroundColor Green
}

# Check available disk space
Write-Host ""
Write-Host "8. Checking disk space..." -ForegroundColor Yellow
$drive = (Get-Location).Drive
$freeSpace = (Get-PSDrive $drive.Name).Free / 1GB
if ($freeSpace -gt 5) {
    Write-Host "✓ Sufficient disk space: $([math]::Round($freeSpace, 2)) GB free" -ForegroundColor Green
}
else {
    Write-Host "⚠ Low disk space: $([math]::Round($freeSpace, 2)) GB free" -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "=== Validation Summary ===" -ForegroundColor Cyan
Write-Host "✓ Docker setup is ready!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Configure environment: cp .env.docker .env" -ForegroundColor White
Write-Host "  2. Edit .env with secure values" -ForegroundColor White
Write-Host "  3. Build and start: docker compose up -d" -ForegroundColor White
Write-Host "  4. View logs: docker compose logs -f" -ForegroundColor White
Write-Host "  5. Test health: curl http://localhost:8080/actuator/health" -ForegroundColor White
Write-Host ""
Write-Host "For full documentation, see DOCKER.md" -ForegroundColor Gray
