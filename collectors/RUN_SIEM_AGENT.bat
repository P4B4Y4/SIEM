@echo off
REM JFS ICT Services - SIEM Agent with GUI
REM Modern Windows-style interface for real-time event collection

echo.
echo ========================================
echo JFS ICT Services - SIEM Agent
echo ========================================
echo.

REM Check if EXE exists
if not exist "dist\JFS_SIEM_Agent.exe" (
    echo ERROR: JFS_SIEM_Agent.exe not found
    echo Run: python -m PyInstaller --onefile --windowed --name JFS_SIEM_Agent siem_agent_gui_http.py
    pause
    exit /b 1
)

echo Starting JFS ICT Services SIEM Agent...
echo.

REM Run the agent
start "" dist\JFS_SIEM_Agent.exe

echo Agent window opened
