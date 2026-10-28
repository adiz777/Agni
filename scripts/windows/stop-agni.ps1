<#
.SYNOPSIS
    Gracefully stops running Agni process by PID with process tree termination and anti-PID-reuse verification.
.DESCRIPTION
    Reads agni.pid, verifies process identity, terminates the process tree
    (parent and child uvicorn/python workers) so port 8000 is not left orphaned,
    and cleans up the PID file.
#>
[CmdletBinding()]
param ()

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path "$ScriptDir\..\..").Path
$PidFile = Join-Path $ProjectRoot "agni.pid"

if (-not (Test-Path $PidFile)) {
    Write-Host "[i] No agni.pid file found. Agni does not appear to be running." -ForegroundColor DarkGray
    exit 0
}

$targetPid = Get-Content $PidFile -ErrorAction SilentlyContinue
if (-not $targetPid) {
    Write-Warning "agni.pid is empty. Removing invalid file."
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    exit 0
}

Write-Host "[*] Stopping Agni process with PID $targetPid..." -ForegroundColor Cyan

$proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
if ($null -eq $proc) {
    Write-Host "[i] Process $targetPid is not active. Cleaning stale PID file." -ForegroundColor DarkGray
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    exit 0
}

# 1. Process Identity Verification (Anti-PID-Reuse)
$cimProc = Get-CimInstance Win32_Process -Filter "ProcessId = $targetPid" -ErrorAction SilentlyContinue
$procName = if ($cimProc -and $cimProc.Name) { $cimProc.Name.ToLower() } else { $proc.ProcessName.ToLower() }
$cmdLine = if ($cimProc -and $cimProc.CommandLine) { $cimProc.CommandLine.ToLower() } else { "" }

$isValid = ($procName -match "^(python|python3|powershell|pwsh|uvicorn)(\.exe)?$" -or $cmdLine -match "uvicorn|app\.main|agni")
if (-not $isValid) {
    Write-Warning "PID $targetPid is running '$procName' which does not match Agni or Python (Anti-PID-Reuse check). Aborting termination."
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    exit 1
}

# 2. Terminate Process Tree (Parent and Children) to prevent orphaned ports
try {
    # Find all child processes before stopping parent
    $childProcesses = Get-CimInstance Win32_Process -Filter "ParentProcessId = $targetPid" -ErrorAction SilentlyContinue
    foreach ($child in $childProcesses) {
        Write-Host "[*] Stopping child process $($child.Name) (PID: $($child.ProcessId))..." -ForegroundColor DarkGray
        Stop-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
    }

    # Request polite stop of parent process
    Stop-Process -Id $targetPid -ErrorAction SilentlyContinue
    $stopped = $proc.WaitForExit(3000)

    # If processes remain active, enforce tree kill via taskkill /T /F
    if (-not $stopped -or (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
        Write-Warning "Process tree did not terminate within 3 seconds. Forcing tree termination..."
        & taskkill.exe /PID $targetPid /T /F 2>&1 | Out-Null
    }

    # Verify and kill any surviving children
    foreach ($child in $childProcesses) {
        if (Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue) {
            & taskkill.exe /PID $child.ProcessId /F 2>&1 | Out-Null
        }
    }

    Write-Host "[+] Agni (PID: $targetPid) and all child processes stopped successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to terminate process $($targetPid): $_"
} finally {
    if (Test-Path $PidFile) {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
}
