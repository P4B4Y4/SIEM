@echo off
REM JFS SIEM - Collector Server Service Installer
REM This script installs the collector server as a Windows Service
REM Requires Administrator privileges

echo.
echo ======================================================================
echo JFS SIEM - Collector Server Service Installer
echo ======================================================================
echo.
echo This script will install the agent collector server as a Windows Service.
echo The service will:
echo   - Start automatically on system boot
echo   - Run continuously in the background
echo   - Restart automatically if it crashes
echo   - Continue running even after user logout
echo.
echo REQUIREMENTS:
echo   - Administrator privileges (this window will request elevation)
echo   - Python 3.8+ installed and in PATH
echo   - Port 9999 open in Windows Firewall
echo.
echo Press any key to continue...
pause >nul

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ERROR: This script requires Administrator privileges!
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo.
echo Starting PowerShell installer...
echo.

REM Get the directory where this script is located
cd /d "%~dp0"

REM Run the PowerShell installer script
powershell -NoProfile -ExecutionPolicy Bypass -File "install_collector_service.ps1"

if %errorLevel% equ 0 (
    echo.
    echo ======================================================================
    echo SUCCESS: Collector service installed!
    echo ======================================================================
    echo.
    echo The collector server is now running as a Windows Service.
    echo.
    echo To verify it's running:
    echo   1. Open Services (services.msc)
    echo   2. Look for "JFS SIEM Agent Collector Server"
    echo   3. Status should be "Running"
    echo.
    echo To view logs:
    echo   1. Open PowerShell as Administrator
    echo   2. Run: Get-Content "%~dp0collector_service.log" -Tail 50
    echo.
) else (
    echo.
    echo ======================================================================
    echo ERROR: Installation failed!
    echo ======================================================================
    echo.
    echo Please check:
    echo   1. You have Administrator privileges
    echo   2. Python is installed: python --version
    echo   3. Port 9999 is not blocked by firewall
    echo   4. Database is accessible
    echo.
)

pause
