<#
.SYNOPSIS
    Registers Agni as an unattended user-level background task in Windows Task Scheduler.
.DESCRIPTION
    Requires explicit user consent before configuring background startup.
    Runs under the current user's logon session with least privilege (no Admin required).
.PARAMETER Consent
    Bypasses the interactive prompt by affirming explicit consent.
.PARAMETER TaskName
    Optional custom task name (default: AgniEndpointMonitor).
#>
[CmdletBinding()]
param (
    [switch]$Consent,
    [string]$TaskName = "AgniEndpointMonitor"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path "$ScriptDir\..\..").Path
$TemplateXml = Join-Path $ScriptDir "task-scheduler.xml"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Agni Background Task Scheduler Registration (R3)            " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Enforce Explicit User Consent Gate
if (-not $Consent) {
    Write-Host "`n[CONSENT REQUIRED]" -ForegroundColor Yellow
    Write-Host "This will configure Agni to launch automatically in the background" -ForegroundColor White
    Write-Host "whenever current user '$env:USERNAME' logs into Windows." -ForegroundColor White
    Write-Host "The process binds exclusively to 127.0.0.1:8000 (Loopback)." -ForegroundColor White
    Write-Host "You can remove it at any time with .\scripts\uninstall\uninstall.ps1`n" -ForegroundColor DarkGray

    $confirmation = Read-Host "Do you explicitly consent to registering this background task? (yes/no)"
    if ($confirmation -notmatch "^(y|yes)$") {
        Write-Warning "Registration cancelled: Explicit user consent was not granted."
        exit 1
    }
}

Write-Host "[+] Consent confirmed. Preparing Task Scheduler definition..." -ForegroundColor Green

if (-not (Test-Path $TemplateXml)) {
    Write-Error "Task template XML not found at $TemplateXml"
    exit 1
}

# 2. Render Template with Absolute Path
$xmlContent = Get-Content -Path $TemplateXml -Raw
$resolvedContent = $xmlContent.Replace("{{AGNI_PROJECT_ROOT}}", $ProjectRoot)

$tempXml = Join-Path $env:TEMP "agni-task-tmp.xml"
Set-Content -Path $tempXml -Value $resolvedContent -Encoding UTF8 -Force

try {
    # 3. Register Task via schtasks under current user context
    Write-Host "[*] Registering task '$TaskName' under user '$env:USERNAME'..." -ForegroundColor Cyan
    $output = & schtasks.exe /Create /TN $TaskName /XML $tempXml /F 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Task '$TaskName' successfully registered!" -ForegroundColor Green
        Write-Host "    Trigger : At user logon ($env:USERNAME)" -ForegroundColor DarkGray
        Write-Host "    Action  : powershell.exe start-agni.ps1 -NoBrowser" -ForegroundColor DarkGray
        Write-Host "    Status  : Ready" -ForegroundColor DarkGray
        exit 0
    } else {
        throw "schtasks failed with exit code $($LASTEXITCODE): $output"
    }
} catch {
    if ($_ -match "Access is denied") {
        Write-Warning "Windows requires Administrator privileges to register scheduled tasks in the Task Scheduler database. Please re-run from an elevated PowerShell session or use foreground runner .\scripts\windows\start-agni.ps1."
    }
    Write-Error "Failed to register Scheduled Task: $_"
    exit 1
} finally {
    if (Test-Path $tempXml) {
        Remove-Item $tempXml -Force -ErrorAction SilentlyContinue
    }
}
