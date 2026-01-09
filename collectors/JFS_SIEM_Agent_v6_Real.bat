@echo off
REM JFS SIEM Agent v6 with Real Features
REM This batch file runs the Python agent with real implementations

cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org
    pause
    exit /b 1
)

REM Run the enhanced agent with real features
python jfs_agent_enhanced.py

if errorlevel 1 (
    echo.
    echo Error: Failed to run agent
    echo Please ensure all dependencies are installed:
    echo pip install tkinter requests psutil pillow pyautogui pywin32
    pause
    exit /b 1
)
