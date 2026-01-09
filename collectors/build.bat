@echo off
REM Build JFS SIEM Agent EXE

echo.
echo ======================================================================
echo JFS SIEM - Building Agent GUI EXE
echo ======================================================================
echo.

REM Kill any running instances
echo Stopping any running instances...
taskkill /F /IM JFS_SIEM_Agent.exe >nul 2>&1

REM Wait a moment
timeout /t 2 /nobreak >nul

REM Clean old build
echo Cleaning old build files...
if exist dist rmdir /s /q dist >nul 2>&1
if exist build rmdir /s /q build >nul 2>&1
if exist *.spec del /q *.spec >nul 2>&1

echo.
echo Building new EXE...
python -m PyInstaller --onefile --windowed --name=JFS_SIEM_Agent agent_gui.py

echo.
echo ======================================================================
if exist dist\JFS_SIEM_Agent.exe (
    echo ✓ BUILD SUCCESSFUL
    echo ======================================================================
    echo EXE Location: %cd%\dist\JFS_SIEM_Agent.exe
    echo.
    echo Next steps:
    echo 1. Copy JFS_SIEM_Agent.exe to remote PC
    echo 2. Double-click to run
    echo 3. Enter collector IP and click Install Service
    echo ======================================================================
) else (
    echo ✗ BUILD FAILED
    echo ======================================================================
)

pause
