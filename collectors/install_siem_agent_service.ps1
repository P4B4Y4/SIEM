# JFS ICT Services - SIEM Agent Windows Service Installer
# Run as Administrator

param(
    [string]$AgentPath = "d:\xamp\htdocs\SIEM\collectors-fixed\dist\SIEM_Agent_HTTP.exe",
    [string]$ServerIP = "192.168.1.52",
    [string]$Port = "80",
    [string]$PCName = $env:COMPUTERNAME
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "JFS ICT Services - SIEM Agent Service" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must run as Administrator" -ForegroundColor Red
    exit 1
}

Write-Host "Installing JFS SIEM Agent as Windows Service..." -ForegroundColor Yellow
Write-Host "Agent: $AgentPath" -ForegroundColor Gray
Write-Host "Server: $ServerIP`:$Port" -ForegroundColor Gray
Write-Host "PC Name: $PCName" -ForegroundColor Gray
Write-Host ""

# Check if agent exists
if (-not (Test-Path $AgentPath)) {
    Write-Host "ERROR: Agent EXE not found at $AgentPath" -ForegroundColor Red
    exit 1
}

# Stop existing service if running
$serviceName = "JFSSIEMAgent"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    Write-Host "Removing existing service..." -ForegroundColor Yellow
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create service using NSSM (if available) or native SC
$nssm = "C:\nssm\nssm.exe"
if (Test-Path $nssm) {
    Write-Host "Using NSSM for service installation..." -ForegroundColor Green
    
    # Install service with NSSM
    & $nssm install $serviceName "$AgentPath" "--server $ServerIP --port $Port --name $PCName" | Out-Null
    & $nssm set $serviceName AppDirectory "d:\xamp\htdocs\SIEM\collectors-fixed" | Out-Null
    & $nssm set $serviceName AppStdout "d:\xamp\htdocs\SIEM\logs\siem-agent.log" | Out-Null
    & $nssm set $serviceName AppStderr "d:\xamp\htdocs\SIEM\logs\siem-agent.log" | Out-Null
    & $nssm set $serviceName AppRotateFiles 1 | Out-Null
    & $nssm set $serviceName Start SERVICE_AUTO_START | Out-Null
    
    Write-Host "Service installed with NSSM" -ForegroundColor Green
} else {
    Write-Host "NSSM not found, using native SC..." -ForegroundColor Yellow
    Write-Host "Note: For better reliability, install NSSM from https://nssm.cc/download" -ForegroundColor Gray
    
    # Create batch wrapper
    $batchFile = "d:\xamp\htdocs\SIEM\collectors-fixed\siem-agent-service.bat"
    $batchContent = @"
@echo off
REM JFS ICT Services - SIEM Agent Service Wrapper
cd /d d:\xamp\htdocs\SIEM\collectors-fixed
dist\SIEM_Agent_HTTP.exe --server $ServerIP --port $Port --name $PCName
"@
    
    Set-Content -Path $batchFile -Value $batchContent -Encoding ASCII
    Write-Host "Created batch wrapper: $batchFile" -ForegroundColor Green
    
    # Create service with SC
    & sc.exe create $serviceName binPath= "`"$batchFile`"" start= auto | Out-Null
    Write-Host "Service created with SC" -ForegroundColor Green
}

# Start service
Write-Host ""
Write-Host "Starting service..." -ForegroundColor Yellow
Start-Service -Name $serviceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Verify service
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "SUCCESS! Service installed and running" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Service Name: $serviceName" -ForegroundColor Gray
    Write-Host "Status: Running" -ForegroundColor Green
    Write-Host "Startup Type: Automatic" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The agent will:" -ForegroundColor Cyan
    Write-Host "  ✓ Start automatically on system boot" -ForegroundColor Green
    Write-Host "  ✓ Run continuously in background" -ForegroundColor Green
    Write-Host "  ✓ Auto-restart if it crashes" -ForegroundColor Green
    Write-Host "  ✓ Continue after user logout" -ForegroundColor Green
    Write-Host ""
    Write-Host "Management Commands:" -ForegroundColor Cyan
    Write-Host "  net start $serviceName" -ForegroundColor Gray
    Write-Host "  net stop $serviceName" -ForegroundColor Gray
    Write-Host "  Get-Service $serviceName" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "ERROR: Service failed to start" -ForegroundColor Red
    Write-Host "Check: d:\xamp\htdocs\SIEM\logs\siem-agent.log" -ForegroundColor Yellow
    exit 1
}
