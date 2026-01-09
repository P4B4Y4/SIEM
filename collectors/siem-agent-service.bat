@echo off
REM JFS ICT Services - SIEM Agent Service
cd /d d:\xamp\htdocs\SIEM\collectors-fixed
dist\SIEM_Agent_HTTP.exe --server 192.168.1.19 --port 80 --name LAPTOP-BR3IMEK8
