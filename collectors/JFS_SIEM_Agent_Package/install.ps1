# JFS SIEM Agent Installation Script
# Run as Administrator

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('install', 'start', 'stop', 'remove', 'status')]
    [string]$Action
)

$exePath = Join-Path $PSScriptRoot "JFS_SIEM_Agent.exe"

if (-not (Test-Path $exePath)) {
    Write-Host "✗ Error: JFS_SIEM_Agent.exe not found" -ForegroundColor Red
    exit 1
}

Write-Host "JFS SIEM Agent - $Action" -ForegroundColor Cyan
Write-Host "=" * 50

switch ($Action) {
    'install' {
        Write-Host "Installing as Windows Service..."
        & $exePath install
        Write-Host "✓ Installation complete!" -ForegroundColor Green
    }
    'start' {
        Write-Host "Starting service..."
        & $exePath start
        Write-Host "✓ Service started!" -ForegroundColor Green
    }
    'stop' {
        Write-Host "Stopping service..."
        & $exePath stop
        Write-Host "✓ Service stopped!" -ForegroundColor Green
    }
    'remove' {
        Write-Host "Removing service..."
        & $exePath remove
        Write-Host "✓ Service removed!" -ForegroundColor Green
    }
    'status' {
        Get-Service JFSSIEMAgent -ErrorAction SilentlyContinue | Select-Object Status, DisplayName
    }
}
