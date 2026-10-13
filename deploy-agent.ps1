<#
.SYNOPSIS
    Deploy Chael SIEM agent on a Windows endpoint - auto-installs Python,
    downloads agent files, and registers with the SIEM.

.DESCRIPTION
    Run this script on the target machine to install the Chael agent.
    It will:
      1. Check for Python 3.9+ and install it if missing (silent install)
      2. Download agent.py and dependencies from the SIEM server
      3. Install pip packages (requests, psutil, pywin32, etc.)
      4. Start the agent (auto-registers with the SIEM)

    Usage:
      .\deploy-agent.ps1 -SiemUrl "http://192.168.1.100:8000"

.PARAMETER SiemUrl
    URL of the Chael SIEM API gateway (e.g. http://192.168.1.100:8000)

.PARAMETER AgentName
    Display name for the agent (defaults to machine hostname)

.PARAMETER AgentId
    Pre-registered agent ID. When provided with -AgentKey, skips auto-registration
    and authenticates directly with the SIEM.

.PARAMETER AgentKey
    Pre-registered agent key. When provided with -AgentId, skips auto-registration
    and authenticates directly with the SIEM.

.PARAMETER AgentDir
    Local directory to install the agent into (default: $env:ProgramFiles\Chael\agent)

.PARAMETER NoStart
    If set, only install files and dependencies - do not start the agent

.EXAMPLE
    .\deploy-agent.ps1 -SiemUrl "http://10.0.0.5:8000"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SiemUrl,

    [string]$AgentName = $env:COMPUTERNAME,

    [string]$AgentId = "",
    [string]$AgentKey = "",

    [string]$AgentDir = "$env:ProgramFiles\Chael\agent",
    [string]$WindowsEventIds = "",
    [switch]$NoSSLVerify,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator. The scheduled task (auto-start on boot) requires elevation." -ForegroundColor Yellow
    Write-Host "  The agent will still install and launch, but will not auto-start after reboot." -ForegroundColor Yellow
    Write-Host "  To fix, re-run this script in an elevated PowerShell window." -ForegroundColor Yellow
    Write-Host ""
}

# Bypass SSL verification if requested (for self-signed certs)
if ($NoSSLVerify) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

# Helper: Write colored output
function Write-Step($msg) {
    Write-Host ">>> $msg" -ForegroundColor Cyan
}

# Stop any existing agent processes and scheduled task
Write-Step "Stopping any existing Chael agent..."
try {
    $existingTask = Get-ScheduledTask -TaskName "ChaelSIEM-Agent" -ErrorAction SilentlyContinue
    if ($existingTask) {
        Stop-ScheduledTask -TaskName "ChaelSIEM-Agent" -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName "ChaelSIEM-Agent" -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  Removed old scheduled task." -ForegroundColor Gray
    }
} catch { Write-Host "  WARNING: Could not remove scheduled task: $_" -ForegroundColor Yellow }

# Kill any existing Chael agent Python processes
Get-Process -Name python* -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    } catch { Write-Host "  WARNING: Could not stop process $($_.Id): $_" -ForegroundColor Yellow }
}
Start-Sleep -Seconds 1

# Clear old log file
$logFile = "$env:TEMP\chael-agent.log"
if (Test-Path $logFile) {
    try { Remove-Item $logFile -Force -ErrorAction SilentlyContinue } catch {}
    Write-Host "  Cleared old agent log." -ForegroundColor Gray
}

# Step 1: Check / Install Python
Write-Step "Checking for Python 3.9+..."

$python = $null
$pyVersion = $null

foreach ($cmd in @("python", "python3")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 9) {
                $python = (Get-Command $cmd).Source
                $pyVersion = "$major.$minor"
                break
            }
        }
    } catch {}
}

if (-not $python) {
    Write-Step "Python 3.9+ not found. Downloading Python 3.12.9..."

    $pythonInstaller = "$env:TEMP\python-3.12.9-amd64.exe"
    $pythonUrl = "https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe"

    try {
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
    } catch {
        Write-Host "ERROR: Failed to download Python from $pythonUrl" -ForegroundColor Red
        Write-Host "Please install Python 3.9+ manually from https://www.python.org/downloads/" -ForegroundColor Yellow
        exit 1
    }

    Write-Step "Installing Python 3.12.9 (silent)..."
    $proc = Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Host "ERROR: Python installer failed with exit code $($proc.ExitCode)" -ForegroundColor Red
        exit 1
    }

    # Refresh PATH in current session
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")

    # Locate the newly installed Python
    $python = (Get-Command "python" -ErrorAction SilentlyContinue).Source
    if (-not $python) {
        $python = "$env:ProgramFiles\Python313\python.exe"
        if (-not (Test-Path $python)) {
            Write-Host "ERROR: Python installed but binary not found in PATH." -ForegroundColor Red
            Write-Host "Restart your terminal or manually add Python to PATH, then re-run this script." -ForegroundColor Yellow
            exit 1
        }
    }

    Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue
    Write-Step "Python 3.12.9 installed successfully at: $python"
} else {
    Write-Step "Python $pyVersion found at: $python"
}

# Step 2: Create agent directory
Write-Step "Creating agent directory: $AgentDir"
New-Item -ItemType Directory -Path $AgentDir -Force | Out-Null

# Step 3: Download agent files from SIEM server
Write-Step "Downloading agent files from $SiemUrl..."

$agentFiles = @(
    "agent.py",
    "requirements.txt",
    "response.py",
    "pre_filter.py",
    "agent_registration.py",
    "yara_scanner.py",
    "registry_monitor.py",
    "docker_monitor.py",
    "cis_benchmark.py",
    "vuln_scanner.py",
    "auto_update.py"
)

$downloaded = $false
$baseUrl = "$SiemUrl/api/agent/static"
foreach ($file in $agentFiles) {
    try {
        Invoke-WebRequest -Uri "$baseUrl/$file" -OutFile "$AgentDir\$file" -UseBasicParsing -ErrorAction Stop
        Write-Host "  Downloaded: $file" -ForegroundColor Gray
        $downloaded = $true
    } catch {
        Write-Host "  WARNING: Could not download $file from SIEM server" -ForegroundColor Yellow
    }
}

if (-not $downloaded) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $repoAgentDir = Join-Path $scriptDir "services\agent"
    if (Test-Path "$repoAgentDir\agent.py") {
        Write-Step "Copying agent files from local repo: $repoAgentDir"
        Copy-Item -Path "$repoAgentDir\*" -Destination $AgentDir -Recurse -Force
        $downloaded = $true
    } else {
        Write-Host "WARNING: Could not download agent files from SIEM or find local copy." -ForegroundColor Yellow
        Write-Host "Please manually copy the contents of services/agent/ to $AgentDir" -ForegroundColor Yellow
        Write-Host "Or clone the repo: git clone https://github.com/your-org/chael-siem.git" -ForegroundColor Yellow
    }
}

if ($downloaded) {
    Write-Step "Agent files ready at $AgentDir"
}

# Ensure Windows Event Log service is running (required for windows-events mode)
$eventLogService = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
if ($eventLogService -and $eventLogService.Status -ne "Running") {
    Write-Step "Starting Windows Event Log service..."
    Start-Service -Name "EventLog" -ErrorAction SilentlyContinue
}

# Add Windows Firewall rule for the agent
$fwRuleName = "Chael SIEM Agent"
$existingRule = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
if (-not $existingRule) {
    Write-Step "Adding Windows Firewall rule for agent outbound traffic..."
    try {
        New-NetFirewallRule -DisplayName $fwRuleName -Direction Outbound -Program "$python" -Action Allow -Profile Any -Description "Allows Chael SIEM agent to communicate with the SIEM server" -ErrorAction Stop | Out-Null
        Write-Host "  Firewall rule created." -ForegroundColor Gray
    } catch {
        Write-Host "  WARNING: Could not create firewall rule: $_" -ForegroundColor Yellow
        Write-Host "  (This is non-critical; the agent will still run.)" -ForegroundColor Yellow
    }
}

# Step 4: Install Python dependencies
Write-Step "Installing Python dependencies..."
& $python -m pip install --upgrade pip --quiet
if ($LASTEXITCODE -ne 0) { Write-Host "WARNING: pip upgrade failed, continuing..." -ForegroundColor Yellow }

& $python -m pip install requests psutil --quiet
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: Failed to install core dependencies" -ForegroundColor Red; exit 1 }

# pywin32 is optional — agent falls back to wevtutil if unavailable
& $python -m pip install pywin32 --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    try {
        $pyDir = Split-Path -Parent $python
        & "$pyDir\Scripts\pywin32_postinstall.py" -install 2>&1 | Out-Null
    } catch {
        Write-Host "  NOTE: pywin32 post-install skipped (non-critical)" -ForegroundColor Yellow
    }
}
& $python -m pip install watchdog --quiet 2>&1 | Out-Null
& $python -m pip install docker --quiet 2>&1 | Out-Null

try {
    & $python -m pip install yara-python --quiet 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "exit code $LASTEXITCODE" }
} catch {
    Write-Host "  NOTE: yara-python not installed (optional, requires Visual C++ build tools)" -ForegroundColor Yellow
}

Write-Step "Dependencies installed."

# Step 5: Start the agent
if (-not $NoStart) {
    Write-Step "Starting Chael SIEM agent..."
    Write-Host "Agent name: $AgentName" -ForegroundColor Gray
    Write-Host "SIEM URL: $SiemUrl" -ForegroundColor Gray
    Write-Host ""

    $authArgs = "--agent-name '$AgentName'"
    $authArgsBatch = "--agent-name ""$AgentName"""
    if ($AgentId -and $AgentKey) {
        $authArgs += " --agent-id '$AgentId' --agent-key '$AgentKey'"
        $authArgsBatch += " --agent-id ""$AgentId"" --agent-key ""$AgentKey"""
    }
    if ($WindowsEventIds) {
        $authArgs += " --windows-event-ids '$WindowsEventIds'"
        $authArgsBatch += " --windows-event-ids ""$WindowsEventIds"""
    }

    # Write a batch launcher for the agent
    $launcherPath = "$AgentDir\start-agent.bat"
    $logFile = "$env:TEMP\chael-agent.log"
    $launcherContent = @"
@echo off
REM Chael SIEM Agent Launcher (auto-generated by deploy-agent.ps1)
"$python" "$AgentDir\agent.py" --siem-url "$SiemUrl" $authArgsBatch >> "$logFile" 2>&1
"@
    $launcherContent | Out-File -FilePath $launcherPath -Encoding ascii

    # Create a Windows scheduled task for auto-start on boot
    $taskName = "ChaelSIEM-Agent"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$launcherPath`""
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $taskExists) {
        Write-Step "Creating scheduled task '$taskName' for auto-start on boot..."
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        try {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
            Write-Step "Scheduled task created. Agent will auto-start on boot."
        } catch {
            Write-Host "WARNING: Could not create scheduled task: $_" -ForegroundColor Yellow
            Write-Host "You can manually run the agent via: $launcherPath" -ForegroundColor Yellow
        }
    } else {
        Write-Step "Scheduled task '$taskName' already exists - updating action..."
        try {
            Set-ScheduledTask -TaskName $taskName -Action $action | Out-Null
        } catch {
            Write-Host "WARNING: Could not update scheduled task: $_" -ForegroundColor Yellow
        }
    }

    # Launch agent now
    Write-Step "Launching agent now..."
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$launcherPath`"" -WindowStyle Hidden

    Write-Host ""
    Write-Host "OK Agent deployment complete!" -ForegroundColor Green
    Write-Host "  Agent directory: $AgentDir" -ForegroundColor Green
    Write-Host "  Launcher: $launcherPath" -ForegroundColor Green
    Write-Host "  Scheduled task: $taskName (auto-starts on boot)" -ForegroundColor Green
    Write-Host "  To view agent logs, check: $logFile" -ForegroundColor Green
} else {
    Write-Step "Installation complete (--NoStart flag set)."
    Write-Host "Agent files are in: $AgentDir" -ForegroundColor Green
    Write-Host "Run the agent manually with:" -ForegroundColor Cyan
    Write-Host "  $python $AgentDir\agent.py --siem-url $SiemUrl --agent-name ""$AgentName""" -ForegroundColor Cyan
}
