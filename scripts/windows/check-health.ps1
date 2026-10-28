<#
.SYNOPSIS
    Probes Agni endpoint health and returns exit code 0 on healthy.
.DESCRIPTION
    Queries http://127.0.0.1:8000/api/v1/health and displays status, version,
    platform, and sensor diagnostics.
#>
[CmdletBinding()]
param (
    [string]$Endpoint = "http://127.0.0.1:8000/api/v1/health"
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Probing Agni health at $Endpoint..." -ForegroundColor Cyan

try {
    $response = Invoke-RestMethod -Uri $Endpoint -Method Get -TimeoutSec 5 -ErrorAction Stop
    
    # Handle response envelope if wrapped in ApiResponse
    $data = if ($response.data) { $response.data } else { $response }
    
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "               Agni Health Status: HEALTHY                  " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " Status   : $($data.status)" -ForegroundColor White
    Write-Host " Version  : $($data.version)" -ForegroundColor White
    Write-Host " Platform : $($data.platform)" -ForegroundColor White
    Write-Host " Mode     : $($data.mode)" -ForegroundColor White
    if ($data.uptime_seconds) {
        Write-Host " Uptime   : $([math]::Round($data.uptime_seconds, 2)) seconds" -ForegroundColor White
    }
    Write-Host " Checked  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -ForegroundColor DarkGray
    exit 0
} catch {
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "              Agni Health Status: UNREACHABLE               " -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " Error    : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host " Target   : $Endpoint" -ForegroundColor DarkGray
    Write-Host "`n[!] Agni is not responding. Ensure the service is started with .\scripts\windows\start-agni.ps1" -ForegroundColor Yellow
    exit 1
}
