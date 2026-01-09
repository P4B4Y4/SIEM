@echo off
REM Start the scheduled event collector
REM This will run in the background and collect events automatically

echo Starting JFS SIEM Scheduled Event Collector...
echo.
echo The collector will run in the background and collect events automatically.
echo To stop it, close this window or press Ctrl+C.
echo.

cd /d "%~dp0"
python scheduled_collector.py

pause
