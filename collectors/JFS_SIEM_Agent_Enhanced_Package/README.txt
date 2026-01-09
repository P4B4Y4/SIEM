# JFS SIEM Enhanced Agent - Deployment Package

## What's Included
- JFS_SIEM_Agent_Enhanced.exe - Complete agent with all advanced features

## Features
✓ 82+ Advanced Security Features
✓ Credential Extraction (Chrome, Firefox, Windows)
✓ Process Injection & Monitoring
✓ Remote Command Execution
✓ Screenshot Capture
✓ File Operations
✓ System Information
✓ Network Reconnaissance
✓ Persistence Mechanisms
✓ Anti-Analysis Detection
✓ And much more...

## Installation

### Quick Start
1. Double-click JFS_SIEM_Agent_Enhanced.exe
2. Configure collector IP and port in GUI
3. Click "Install Service"
4. Click "Start Service"

### Manual Service Installation
```
JFS_SIEM_Agent_Enhanced.exe install
JFS_SIEM_Agent_Enhanced.exe start
```

## Configuration
Default settings:
- Collector IP: 192.168.1.100
- Collector Port: 9999

Change via GUI or edit agent_config.json

## Service Management

Start: `JFS_SIEM_Agent_Enhanced.exe start`
Stop: `JFS_SIEM_Agent_Enhanced.exe stop`
Remove: `JFS_SIEM_Agent_Enhanced.exe remove`
Status: `Get-Service JFSSIEMAgent`

## Logs
Location: %APPDATA%\JFS_SIEM_Agent\logs\

## Version
JFS SIEM Enhanced Agent v7.0
Build Date: 2025-12-18 10:52:00
