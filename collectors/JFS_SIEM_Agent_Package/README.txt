# JFS SIEM Agent - Standalone Deployment

## What's Included
- JFS_SIEM_Agent.exe - Complete agent with all dependencies bundled

## Installation

### Option 1: Install as Windows Service (Recommended)

1. Open Command Prompt as Administrator
2. Run:
   ```
   JFS_SIEM_Agent.exe install
   ```
3. Start the service:
   ```
   JFS_SIEM_Agent.exe start
   ```
4. Verify:
   ```
   Get-Service JFSSIEMAgent
   ```

### Option 2: Run Directly

1. Open Command Prompt
2. Run:
   ```
   JFS_SIEM_Agent.exe
   ```

## Configuration

The agent connects to:
- **Server:** 192.168.1.100
- **Port:** 9999

To change these settings, edit the EXE configuration (see Advanced section)

## Service Management

### Start Service
```
JFS_SIEM_Agent.exe start
```

### Stop Service
```
JFS_SIEM_Agent.exe stop
```

### Remove Service
```
JFS_SIEM_Agent.exe remove
```

### Check Status
```
Get-Service JFSSIEMAgent
```

## Logs

Logs are saved to:
```
%APPDATA%\JFS_SIEM_Agent\logs\jfs_agent_service.log
```

## Features

✓ Single EXE file - no dependencies to install
✓ Runs as Windows Service
✓ Persistent connection to SIEM collector
✓ Auto-reconnect on failure
✓ Continuous event collection
✓ Detailed logging
✓ Auto-starts on system reboot

## Troubleshooting

### Service won't start
- Check if collector is running (192.168.1.100:9999)
- Check firewall allows port 9999
- Check logs for errors

### No events being collected
- Verify collector is accessible
- Check Windows Event Viewer for events
- Check logs for connection errors

### Logs location
```
%APPDATA%\JFS_SIEM_Agent\logs\
```

## Support

For issues, check the logs or contact your SIEM administrator.

## Version
JFS SIEM Agent v1.0 (Standalone)
