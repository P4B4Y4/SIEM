@echo off
REM JFS ICT Services - SIEM Agent Service Installer
REM Run as Administrator

echo.
echo ========================================
echo JFS ICT Services - SIEM Agent Service
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must run as Administrator
    echo.
    echo Right-click this file and select "Run as Administrator"
    pause
    exit /b 1
)

REM Get parameters
set SERVER_IP=192.168.1.52
set PORT=80
set PC_NAME=%COMPUTERNAME%

echo Installing JFS SIEM Agent as Windows Service...
echo Server: %SERVER_IP%:%PORT%
echo PC Name: %PC_NAME%
echo.

REM Run PowerShell script
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_siem_agent_service.ps1" -ServerIP "%SERVER_IP%" -Port "%PORT%" -PCName "%PC_NAME%"

if %errorlevel% equ 0 (
    echo.
    echo Service installation complete!
    echo The agent will start automatically on next reboot.
) else (
    echo.
    echo Service installation failed!
    echo Check the error messages above.
)

pause
