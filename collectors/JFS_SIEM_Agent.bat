@echo off
REM JFS SIEM Agent - Batch Wrapper
REM This runs the Python script directly

setlocal enabledelayedexpansion

REM Get the directory where this batch file is located
set SCRIPT_DIR=%~dp0

REM Run the Python script
python "%SCRIPT_DIR%jfs_agent_console.py" %*

REM Keep window open if there's an error
if errorlevel 1 (
    echo.
    echo Error occurred. Press any key to exit...
    pause
)
