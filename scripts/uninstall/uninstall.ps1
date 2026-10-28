<#
.SYNOPSIS
    Clean uninstallation and teardown script for Agni on Windows.
.DESCRIPTION
    Stops running processes with process tree termination and anti-PID-reuse verification,
    unregisters the scheduled task, removes PID files and runtime temp artifacts,
    and optionally archives or retains the database.
.PARAMETER PurgeData
    If specified, deletes the SQLite database directory (data/). Otherwise preserved.
#>
[CmdletBinding()]
param (
    [switch]$PurgeData
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path "$ScriptDir\..\..").Path
$PidFile = Join-Path $ProjectRoot "agni.pid"
$TaskName = "AgniEndpointMonitor"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         Agni Platform Uninstallation & Teardown            " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Stop running Agni process tree if active
if (Test-Path $PidFile) {
    $targetPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($targetPid) {
        $proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
        if ($proc) {
            # Anti-PID-Reuse check
            $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId = $targetPid" -ErrorAction SilentlyContinue
            $procName = if ($cimProc -and $cimProc.Name) { $cimProc.Name.ToLower() } else { $proc.ProcessName.ToLower() }
            $cmdLine = if ($cimProc -and $cimProc.CommandLine) { $cimProc.CommandLine.ToLower() } else { "" }
            $isValid = ($procName -match "^(python|python3|powershell|pwsh|uvicorn)(\.exe)?$" -or $cmdLine -match "uvicorn|app\.main|agni")
            if ($isValid) {
                Write-Host "[*] Terminating active Agni process tree (PID: $targetPid)..." -ForegroundColor Cyan
                # Terminate child processes and parent process tree
                $childProcesses = Get-CimInstance Win32_Process -Filter "ParentProcessId = $targetPid" -ErrorAction SilentlyContinue
                & taskkill.exe /PID $targetPid /T /F 2>&1 | Out-Null
                foreach ($child in $childProcesses) {
                    if (Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue) {
                        & taskkill.exe /PID $child.ProcessId /F 2>&1 | Out-Null
                    }
                }
            } else {
                Write-Warning "PID $targetPid ($procName) does not match Agni or Python (Anti-PID-Reuse check). Skipping process termination."
            }
        }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

# 2. Unregister Scheduled Task if present
Write-Host "[*] Checking Windows Task Scheduler for '$TaskName'..." -ForegroundColor Cyan
$taskExists = & schtasks.exe /Query /TN $TaskName 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] Unregistering scheduled task '$TaskName'..." -ForegroundColor Yellow
    & schtasks.exe /Delete /TN $TaskName /F | Out-Null
    Write-Host "[+] Scheduled task removed." -ForegroundColor Green
} else {
    Write-Host "[i] No scheduled task '$TaskName' found." -ForegroundColor DarkGray
}

# 3. Clean up runtime temporary files
$tempArtifacts = @(
    (Join-Path $ProjectRoot "agni.pid"),
    (Join-Path $env:TEMP "agni-task-tmp.xml")
)
foreach ($artifact in $tempArtifacts) {
    if (Test-Path $artifact) {
        Remove-Item $artifact -Force -ErrorAction SilentlyContinue
    }
}

# 4. Handle Database / Telemetry Records
$DataDir = Join-Path $ProjectRoot "data"
if ($PurgeData) {
    if (Test-Path $DataDir) {
        Write-Host "[!] Purging database directory: $DataDir" -ForegroundColor Yellow
        Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Data purged." -ForegroundColor Green
    }
} else {
    Write-Host "[+] Preserved telemetry database directory: $DataDir" -ForegroundColor Green
    Write-Host "    (Use -PurgeData flag if you wish to completely remove telemetry history)" -ForegroundColor DarkGray
}

Write-Host "`n[+] Agni uninstallation completed cleanly." -ForegroundColor Green
