@echo off
REM Start the Agent Collector Server

echo.
echo ======================================================================
echo JFS SIEM - Agent Collector Server
echo ======================================================================
echo.
echo This script starts the collector server that receives events from agents.
echo.
echo Server will listen on: 0.0.0.0:9999
echo.
echo Make sure:
echo   1. Python is installed
echo   2. Database is running and accessible
echo   3. Port 9999 is not blocked by firewall
echo.
echo Press any key to start...
pause >nul

echo.
echo Starting collector server...
echo.

python agent_collector_server.py

echo.
echo Server stopped.
pause
