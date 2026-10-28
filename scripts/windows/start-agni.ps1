<#
.SYNOPSIS
    Interactive foreground startup script for Agni Threat Detection Engine.
.DESCRIPTION
    Validates Python 3.11+, checks dependencies, binds strictly to 127.0.0.1:8000,
    records the running process ID in agni.pid, and launches the FastAPI service.
.PARAMETER NoBrowser
    Prevents automatically opening the default web browser to the dashboard.
.PARAMETER Dev
    Runs the backend in hot-reload development mode.
#>
[CmdletBinding()]
param (
    [switch]$NoBrowser,
    [switch]$Dev
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path "$ScriptDir\..\..").Path
$PidFile = Join-Path $ProjectRoot "agni.pid"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Agni - Local Threat Detection & Monitoring Engine   " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot" -ForegroundColor DarkGray
Write-Host "Network Bind : 127.0.0.1:8000 (Loopback only)" -ForegroundColor DarkGray

# 1. Verify Python 3.11+
try {
    $pythonCmd = "python"
    $pyVersionRaw = & $pythonCmd --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python command not found."
    }
    Write-Host "[+] Python environment detected: $pyVersionRaw" -ForegroundColor Green
} catch {
    Write-Error "Python 3.11+ is required but could not be located on PATH. Please install Python 3.11+ and retry."
    exit 1
}

# 2. Check for active virtual environment
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $pythonCmd = $VenvPython
    Write-Host "[+] Utilizing virtual environment: $VenvPython" -ForegroundColor Green
}

# 3. Check for existing running instance (with anti-PID-reuse verification)
if (Test-Path $PidFile) {
    $existingPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($existingPid) {
        $existingProc = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
        if ($existingProc) {
            $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId = $existingPid" -ErrorAction SilentlyContinue
            $pName = if ($cimProc -and $cimProc.Name) { $cimProc.Name.ToLower() } else { $existingProc.ProcessName.ToLower() }
            $cLine = if ($cimProc -and $cimProc.CommandLine) { $cimProc.CommandLine.ToLower() } else { "" }
            if ($pName -match "^(python|python3|powershell|pwsh|uvicorn)(\.exe)?$" -or $cLine -match "uvicorn|app\.main|agni") {
                Write-Warning "Agni is already running with PID $existingPid. Use .\scripts\windows\stop-agni.ps1 first."
                exit 1
            }
        }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

# 4. Record PID and handle graceful exit
$CurrentPid = $PID
Set-Content -Path $PidFile -Value $CurrentPid -Force

function Cleanup {
    Write-Host "`n[*] Stopping Agni and cleaning up PID file..." -ForegroundColor Yellow
    # Terminate any child processes spawned by this session to prevent orphaned processes
    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $PID" -ErrorAction SilentlyContinue
    foreach ($child in $children) {
        Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $PidFile) {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[+] Shutdown complete." -ForegroundColor Green
}

# Register Ctrl+C / Exit cleanup
try {
    # 5. Open browser if requested
    if (-not $NoBrowser) {
        Start-Job -ScriptBlock {
            Start-Sleep -Seconds 2
            Start-Process "http://127.0.0.1:8000/docs"
        } | Out-Null
    }

    Write-Host "[+] Starting Agni server on 127.0.0.1:8000..." -ForegroundColor Cyan
    Write-Host "[*] Press Ctrl+C to stop.`n" -ForegroundColor DarkYellow

    # 6. Execute Uvicorn server directly from backend directory
    $BackendDir = Join-Path $ProjectRoot "backend"
    $env:PYTHONPATH = "$BackendDir;$ProjectRoot"
    
    $reloadFlag = if ($Dev) { "--reload" } else { "" }
    $cmd = "$pythonCmd -m uvicorn app.main:app --host 127.0.0.1 --port 8000 $reloadFlag"
    
    Push-Location $BackendDir
    try {
        Invoke-Expression $cmd
    } finally {
        Pop-Location
    }
} finally {
    Cleanup
}
