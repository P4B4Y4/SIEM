@echo off
REM Create Task Scheduler task with admin privileges
REM This must be run as Administrator

echo Creating JFS SIEM Event Collector task...
echo.

REM Delete old task if exists
schtasks /delete /TN "JFS SIEM Event Collector" /F >nul 2>&1

REM Create new task
REM At startup trigger
schtasks /create /TN "JFS SIEM Event Collector" ^
    /TR "d:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\start_scheduler.bat" ^
    /SC ONSTART ^
    /RU SYSTEM ^
    /RL HIGHEST ^
    /F

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Task created successfully!
    echo.
    echo Task Details:
    echo   - Name: JFS SIEM Event Collector
    echo   - Trigger: At system startup
    echo   - Run As: SYSTEM (highest privileges)
    echo   - Status: Ready
    echo.
    echo The task will start collecting events at next startup.
    echo.
    echo To run it manually now, use:
    echo   schtasks /run /TN "JFS SIEM Event Collector"
) else (
    echo.
    echo ✗ Error creating task!
    echo This script must be run as Administrator.
    echo.
    echo Right-click this file and select "Run as Administrator"
    pause
    exit /b 1
)

pause
