# Chael SIEM - one-command deploy (Windows).
# Usage:  .\deploy.ps1            (normal start)
#         .\deploy.ps1 -Build     (rebuild images first, then start)
param([switch]$Build)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "  OK: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red; exit 1 }

Step "Checking Docker"
try { docker info 2>$null | Out-Null; if ($LASTEXITCODE -ne 0) { throw "down" } }
catch { Fail "Docker is not running. Start Docker Desktop, wait for green, re-run." }
Ok "Docker engine responding"

if (-not (Test-Path ".env")) {
    Step "Creating .env from .env.example (first run)"
    Copy-Item ".env.example" ".env"
    Write-Host "  Edit .env now to set ADMIN_PASSWORD / OPENSEARCH_PASSWORD / API keys." -ForegroundColor Yellow
    Write-Host "  Press Enter to continue with defaults, or Ctrl+C, edit .env, re-run." -ForegroundColor Yellow
    Read-Host | Out-Null
} else { Ok ".env present" }

if ($Build) {
    Step "Rebuilding images (serial - kind to small boxes)"
    docker compose build
    if ($LASTEXITCODE -ne 0) { Fail "build failed - see output above" }
    Ok "images rebuilt"
}

Step "Starting stack"
docker compose up -d
if ($LASTEXITCODE -ne 0) { Fail "compose up failed" }

Step "Waiting for gateway (up to 5 min)"
$deadline = (Get-Date).AddMinutes(5)
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:8001/health" -TimeoutSec 10 -UseBasicParsing
        if ($r.StatusCode -eq 200) { break }
    } catch { Start-Sleep -Seconds 10 }
}
try { Invoke-WebRequest -Uri "http://localhost:8001/health" -TimeoutSec 15 -UseBasicParsing | Out-Null }
catch { Fail "gateway never became healthy - run: docker compose logs gateway opensearch" }
Ok "gateway healthy"

Write-Host ""
Write-Host "  Dashboard : http://localhost:3000  (admin / ADMIN_PASSWORD from .env)" -ForegroundColor Green
Write-Host "  API       : http://localhost:8001  (https :8443)" -ForegroundColor Green
Write-Host "  Prometheus: http://localhost:9090" -ForegroundColor Green
Write-Host ""
Write-Host "  Next: deploy an agent (AGENT_DEPLOYMENT.md), change default passwords," -ForegroundColor Yellow
Write-Host "  then add threat-intel / SMTP / approver keys from .env.example as needed." -ForegroundColor Yellow
