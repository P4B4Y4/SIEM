@echo off
setlocal

net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set BASE=C:\ProgramData\JFS_SIEM_Agent\service

if exist "%BASE%\JFSSIEMAgentService.exe" (
  "%BASE%\JFSSIEMAgentService.exe" stop >nul 2>&1
  "%BASE%\JFSSIEMAgentService.exe" uninstall >nul 2>&1
)

sc delete JFSSIEMAgent >nul 2>&1

echo Service removed.
pause
exit /b 0
