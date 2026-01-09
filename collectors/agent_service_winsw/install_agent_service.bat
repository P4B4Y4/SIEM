@echo off
setlocal

REM One-click installer for non-technical users.
REM Prompts for UAC automatically, then installs and starts the service.

net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set BASE=C:\ProgramData\JFS_SIEM_Agent\service
set LOGS=%BASE%\logs

if not exist "%BASE%" mkdir "%BASE%" >nul 2>&1
if not exist "%LOGS%" mkdir "%LOGS%" >nul 2>&1

copy /Y "%~dp0JFS_SIEM_Agent_Enhanced_ServiceFix.exe" "%BASE%\JFS_SIEM_Agent_Enhanced_ServiceFix.exe" >nul
copy /Y "%~dp0JFSSIEMAgentService.exe" "%BASE%\JFSSIEMAgentService.exe" >nul
copy /Y "%~dp0JFSSIEMAgentService.xml" "%BASE%\JFSSIEMAgentService.xml" >nul

"%BASE%\JFSSIEMAgentService.exe" uninstall >nul 2>&1
"%BASE%\JFSSIEMAgentService.exe" install
if %errorlevel% neq 0 (
  echo Failed to install service. Check logs: %LOGS%
  pause
  exit /b 1
)

"%BASE%\JFSSIEMAgentService.exe" start
if %errorlevel% neq 0 (
  echo Service installed but failed to start. Check logs: %LOGS%
  pause
  exit /b 1
)

echo Service installed and started successfully.
echo Logs folder: %LOGS%
pause
exit /b 0
