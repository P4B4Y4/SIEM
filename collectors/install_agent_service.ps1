# JFS SIEM - Install Agent as Windows Service
# Run as Administrator on remote PC
# Usage: .\install_agent_service.ps1 -CollectorIP 192.168.1.100 -AgentName PC-NAME

param(
    [Parameter(Mandatory=$true)]
    [string]$CollectorIP,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false)]
    [int]$CollectorPort = 9999,
    
    [Parameter(Mandatory=$false)]
    [string]$PythonPath = "C:\Python311\python.exe"
)

# Check if running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "JFS SIEM - Agent Service Installation" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Check Python installation
if (-NOT (Test-Path $PythonPath)) {
    Write-Host "ERROR: Python not found at $PythonPath" -ForegroundColor Red
    Write-Host "Install Python from https://www.python.org/" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Python found: $PythonPath" -ForegroundColor Green

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentScript = Join-Path $ScriptDir "jfs_agent.py"

if (-NOT (Test-Path $AgentScript)) {
    Write-Host "ERROR: jfs_agent.py not found at $AgentScript" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Agent script found: $AgentScript" -ForegroundColor Green

# Service name
$ServiceName = "JFSSIEMAgent"
$DisplayName = "JFS SIEM Agent - $AgentName"

# Check if service already exists
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Service) {
    Write-Host "⚠ Service already exists. Removing..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Remove-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Create batch file to run Python
$BatchFile = Join-Path $ScriptDir "run_agent.bat"
$BatchContent = @"
@echo off
cd /d "$ScriptDir"
"$PythonPath" jfs_agent.py --server $CollectorIP --port $CollectorPort --name $AgentName
"@

Set-Content -Path $BatchFile -Value $BatchContent
Write-Host "✓ Created batch file: $BatchFile" -ForegroundColor Green

# Create service using NSSM (if available) or SC command
# First try NSSM
$NssmPath = "C:\Program Files\nssm\nssm.exe"
if (Test-Path $NssmPath) {
    Write-Host "✓ Found NSSM, using it to create service..." -ForegroundColor Green
    & $NssmPath install $ServiceName $BatchFile
} else {
    Write-Host "ℹ NSSM not found, using SC command..." -ForegroundColor Yellow
    Write-Host "  (Install NSSM for better service management)" -ForegroundColor Gray
    
    # Create service using SC
    $ServicePath = "`"$BatchFile`""
    sc.exe create $ServiceName binPath= $ServicePath start= auto DisplayName= "$DisplayName"
}

# Start service
Write-Host "`nStarting service..." -ForegroundColor Cyan
Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Check if service is running
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Service.Status -eq "Running") {
    Write-Host "✓ Service is RUNNING" -ForegroundColor Green
} else {
    Write-Host "⚠ Service is not running. Check logs for errors." -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
Write-Host "Agent Name: $AgentName" -ForegroundColor Cyan
Write-Host "Collector: $CollectorIP`:$CollectorPort" -ForegroundColor Cyan
Write-Host "`nTo manage the service:" -ForegroundColor Yellow
Write-Host "  Start:   net start $ServiceName" -ForegroundColor Gray
Write-Host "  Stop:    net stop $ServiceName" -ForegroundColor Gray
Write-Host "  Remove:  sc delete $ServiceName" -ForegroundColor Gray
