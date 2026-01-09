@echo off
REM Fortinet Syslog Listener - Continuous Runner
REM This batch file keeps the PHP listener running continuously

setlocal enabledelayedexpansion

cd /d d:\xamp\htdocs\SIEM

echo.
echo ========================================
echo Fortinet Syslog Listener (Continuous)
echo ========================================
echo.
echo Starting listener on UDP port 514...
echo Press Ctrl+C to stop
echo.

:loop
php -d error_reporting=E_ALL -d display_errors=1 syslog-listener.php
echo.
echo [%date% %time%] Listener exited, restarting in 3 seconds...
timeout /t 3 /nobreak
goto loop
