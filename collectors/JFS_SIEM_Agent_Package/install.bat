@echo off
REM JFS SIEM Agent Installation Script

echo.
echo ========================================
echo JFS SIEM Agent Installation
echo ========================================
echo.

if "%1"=="" (
    echo Usage: install.bat [install^|start^|stop^|remove]
    echo.
    echo Examples:
    echo   install.bat install  - Install as Windows Service
    echo   install.bat start    - Start the service
    echo   install.bat stop     - Stop the service
    echo   install.bat remove   - Remove the service
    echo.
    pause
    exit /b 1
)

if /i "%1"=="install" (
    echo Installing JFS SIEM Agent as Windows Service...
    JFS_SIEM_Agent.exe install
    echo.
    echo ✓ Installation complete!
    echo.
    echo To start the service, run: install.bat start
    pause
    exit /b 0
)

if /i "%1"=="start" (
    echo Starting JFS SIEM Agent service...
    JFS_SIEM_Agent.exe start
    echo.
    echo ✓ Service started!
    pause
    exit /b 0
)

if /i "%1"=="stop" (
    echo Stopping JFS SIEM Agent service...
    JFS_SIEM_Agent.exe stop
    echo.
    echo ✓ Service stopped!
    pause
    exit /b 0
)

if /i "%1"=="remove" (
    echo Removing JFS SIEM Agent service...
    JFS_SIEM_Agent.exe remove
    echo.
    echo ✓ Service removed!
    pause
    exit /b 0
)

echo Unknown command: %1
pause
exit /b 1
