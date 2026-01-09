# -*- coding: utf-8 -*-
# JFS SIEM - Collector Server Windows Service Installer
# Installs the agent collector server as an automatic Windows Service
# Run as Administrator

param(
    [string]$PythonPath = "python",
    [string]$ScriptPath = $PSScriptRoot
)

# Ensure running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "JFS SIEM - Collector Service Installer" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Service configuration
$ServiceName = "JFSSIEMCollector"
$ServiceDisplayName = "JFS SIEM Agent Collector Server"
$ServiceDescription = "Receives event logs from remote JFS SIEM agents and stores in database"
$ScriptFullPath = Join-Path $ScriptPath "agent_collector_server.py"

# Check if Python script exists
if (-not (Test-Path $ScriptFullPath)) {
    Write-Host "ERROR: Script not found: $ScriptFullPath" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Service Name: $ServiceName" -ForegroundColor Gray
Write-Host "[*] Display Name: $ServiceDisplayName" -ForegroundColor Gray
Write-Host "[*] Script Path: $ScriptFullPath" -ForegroundColor Gray
Write-Host ""

# Stop existing service if running
Write-Host "[*] Checking for existing service..." -ForegroundColor Yellow
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Host "[*] Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    Write-Host "[*] Removing existing service..." -ForegroundColor Yellow
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create batch file wrapper for service
$BatchPath = Join-Path $ScriptPath "run_collector.bat"
$BatchContent = @"
@echo off
REM JFS SIEM Collector Server - Service Wrapper
REM This batch file is called by Windows Service

cd /d "$ScriptPath"

REM Run Python script
$PythonPath agent_collector_server.py

REM If script exits, restart after 5 seconds
timeout /t 5 /nobreak
goto start

:start
$PythonPath agent_collector_server.py
goto start
"@

Write-Host "[*] Creating batch file wrapper..." -ForegroundColor Yellow
Set-Content -Path $BatchPath -Value $BatchContent -Encoding ASCII

# Create service using NSSM (Non-Sucking Service Manager) if available, otherwise use sc.exe
Write-Host "[*] Creating Windows Service..." -ForegroundColor Yellow

# Try using NSSM first (more reliable for Python)
$nssmPath = "C:\Program Files\nssm\nssm.exe"
if (Test-Path $nssmPath) {
    Write-Host "[*] Using NSSM to create service..." -ForegroundColor Cyan
    & $nssmPath install $ServiceName $BatchPath
    & $nssmPath set $ServiceName AppDirectory $ScriptPath
    & $nssmPath set $ServiceName AppStdout "$ScriptPath\collector_service.log"
    & $nssmPath set $ServiceName AppStderr "$ScriptPath\collector_service_error.log"
    & $nssmPath set $ServiceName AppRotateFiles 1
    & $nssmPath set $ServiceName AppRotateOnline 1
    & $nssmPath set $ServiceName AppRotateSeconds 86400
    & $nssmPath set $ServiceName AppRotateBytes 10485760
} else {
    # Fallback to sc.exe
    Write-Host "[*] Using sc.exe to create service..." -ForegroundColor Cyan
    & sc.exe create $ServiceName binPath= "$BatchPath" DisplayName= "$ServiceDisplayName" start= auto
}

# Set service description
& sc.exe description $ServiceName "$ServiceDescription" | Out-Null

# Configure service to run as LocalSystem (can access event logs)
& sc.exe config $ServiceName obj= "LocalSystem" | Out-Null

# Enable service to interact with desktop (optional, for debugging)
& sc.exe config $ServiceName type= own | Out-Null

# Start the service
Write-Host "[*] Starting service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Verify service is running
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "[OK] Service started successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Service Status:" -ForegroundColor Cyan
    Get-Service -Name $ServiceName | Format-Table -AutoSize
} else {
    Write-Host "[ERROR] Service failed to start!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Check logs: Get-Content '$ScriptPath\collector_service.log' -Tail 50" -ForegroundColor Gray
    Write-Host "2. Check errors: Get-Content '$ScriptPath\collector_service_error.log' -Tail 50" -ForegroundColor Gray
    Write-Host "3. Verify Python: python --version" -ForegroundColor Gray
    Write-Host "4. Test script: python agent_collector_server.py" -ForegroundColor Gray
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Installation Complete" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Service Details:" -ForegroundColor Cyan
Write-Host "  Name: $ServiceName" -ForegroundColor Gray
Write-Host "  Display: $ServiceDisplayName" -ForegroundColor Gray
Write-Host "  Startup: Automatic" -ForegroundColor Gray
Write-Host "  Account: LocalSystem" -ForegroundColor Gray
Write-Host ""
Write-Host "Management Commands:" -ForegroundColor Cyan
Write-Host "  Start:   net start $ServiceName" -ForegroundColor Gray
Write-Host "  Stop:    net stop $ServiceName" -ForegroundColor Gray
Write-Host "  Status:  Get-Service $ServiceName" -ForegroundColor Gray
Write-Host "  Logs:    Get-Content '$ScriptPath\collector_service.log' -Tail 50" -ForegroundColor Gray
Write-Host ""
