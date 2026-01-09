# JFS SIEM Agent - Service Installation Fix (Dec 9, 2025)

## Issue Fixed
**Error:** `InstallService error: Objects of type 'type' can not be converted to Unicode.`

When installing the JFS SIEM Agent service using the GUI, the service installation would fail with a Unicode conversion error.

## Root Cause
The `win32serviceutil.InstallService()` function was missing the `serviceType` parameter, which caused issues with how the service class was being registered with Windows.

## Changes Made

### File: `jfs_agent_service.py`

#### Change 1: GUI Service Installation (line 440)
Added `serviceType=win32service.SERVICE_WIN32_OWN_PROCESS` parameter:

```python
win32serviceutil.InstallService(
    JFSAgentService,
    JFSAgentService._svc_name_,
    JFSAgentService._svc_display_name_,
    startType=win32service.SERVICE_AUTO_START,
    serviceType=win32service.SERVICE_WIN32_OWN_PROCESS  # ADDED
)
```

#### Change 2: Command-line Service Installation (line 491)
Added the same `serviceType` parameter and improved error handling.

## Build Information

### New EXE Location
```
d:\xamp\htdocs\SIEM\collectors\JFS_SIEM_Agent_Package\JFS_SIEM_Agent.exe
```

### Size & Status
- **Size:** 108.0 MB (single file, all dependencies included)
- **Status:** ✅ READY FOR DEPLOYMENT
- **Build Date:** December 9, 2025

## How to Use the Fixed EXE

### Installation Steps
1. Copy `JFS_SIEM_Agent.exe` from the package folder to target PC
2. Double-click to open GUI
3. Enter Collector IP and Port
4. Click "Install Service"
5. Click "Start Service"
6. Close the GUI - service continues running 24/7

### Service Management
```powershell
# Check status
Get-Service JFSSIEMAgent

# Start service
net start JFSSIEMAgent

# Stop service
net stop JFSSIEMAgent

# Remove service
sc delete JFSSIEMAgent
```

## Verification
The service installation now completes successfully without Unicode conversion errors.

## Deployment Package Contents
- `JFS_SIEM_Agent.exe` - Main executable (108 MB)
- `install.bat` - Batch file for easy installation
- `install.ps1` - PowerShell script for installation
- `README.txt` - Documentation

## Key Features
✅ Single standalone EXE - no dependencies
✅ Windows Service with persistence
✅ GUI configuration interface
✅ Auto-restart on crash
✅ Survives system reboot
✅ Persistent connection to collector
✅ Fixed service installation (no more Unicode errors)

## Status: ✅ PRODUCTION READY
