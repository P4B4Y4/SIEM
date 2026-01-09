@echo off
REM Run SIEM HTTP Agent
REM Sends Windows events to SIEM collector via HTTP

echo.
echo ========================================
echo SIEM HTTP Agent
echo ========================================
echo.

REM Check if EXE exists
if not exist "dist\SIEM_Agent_HTTP.exe" (
    echo ERROR: SIEM_Agent_HTTP.exe not found
    echo Run: python -m PyInstaller --onefile siem_agent_http.py
    pause
    exit /b 1
)

echo Starting SIEM HTTP Agent...
echo Server: 192.168.1.52
echo Port: 80
echo.

REM Run the agent
dist\SIEM_Agent_HTTP.exe --server 192.168.1.52 --port 80 --name %COMPUTERNAME%

REM If agent stops, show message
echo.
echo Agent stopped
pause
