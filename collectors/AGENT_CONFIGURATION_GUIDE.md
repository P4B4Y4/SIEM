# JFS SIEM Agent - Configuration Guide

## Quick Start (5 Minutes)

### Step 1: Copy EXE to Target PC
```
Source: d:\xamp\htdocs\SIEM\collectors-fixed\dist\JFS_SIEM_Agent.exe
Destination: Any folder on target PC (e.g., C:\Program Files\JFS_SIEM_Agent\)
```

### Step 2: Double-click the EXE
- Simple GUI window opens
- Shows 4 buttons: Install Service, Start Service, Stop Service, Remove Service

### Step 3: Configure Collector IP (Optional)
If your collector is NOT at `192.168.1.100:9999`, edit the service file:
- Open: `jfs_agent_service.py` (in same folder as EXE)
- Find line 52-53:
  ```python
  self.server_ip = "192.168.1.100"  # Change this
  self.server_port = 9999            # Change this if needed
  ```
- Change to your collector IP and port
- Rebuild EXE using build script

### Step 4: Install Service
1. Click "Install Service" button
2. Wait for success message
3. Service is now installed as Windows Service

### Step 5: Start Service
1. Click "Start Service" button
2. Wait for success message
3. Service starts collecting events

### Step 6: Verify Service is Running
Open Command Prompt and run:
```
sc query JFSSIEMAgent
```

Expected output:
```
SERVICE_NAME: JFSSIEMAgent
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

---

## Configuration Options

### Collector Server Settings
**File:** `jfs_agent_service.py` (lines 50-53)

```python
self.server_ip = "192.168.1.100"      # Collector IP address
self.server_port = 9999                # Collector port
self.pc_name = socket.gethostname()   # PC name (auto-detected)
```

### Event Log Sources
**File:** `jfs_agent_service.py` (lines 57-62)

The agent collects from these Windows Event Logs:
- **System** - System events
- **Application** - Application events
- **Security** - Security events (requires admin)

### Connection Settings
**File:** `jfs_agent_service.py` (lines 200-210)

```python
self.socket.settimeout(10)  # Connection timeout (seconds)
```

---

## Common Configurations

### Configuration 1: Default (Recommended)
- Collector IP: `192.168.1.100`
- Collector Port: `9999`
- Event Logs: System, Application, Security
- **No changes needed** - Just run the EXE!

### Configuration 2: Custom Collector IP
1. Edit `jfs_agent_service.py`
2. Change line 52:
   ```python
   self.server_ip = "YOUR_COLLECTOR_IP"
   ```
3. Rebuild EXE using build script

### Configuration 3: Custom Port
1. Edit `jfs_agent_service.py`
2. Change line 53:
   ```python
   self.server_port = YOUR_PORT_NUMBER
   ```
3. Rebuild EXE using build script

### Configuration 4: Specific Event Logs Only
1. Edit `jfs_agent_service.py`
2. Find line 57-62 (last_record_numbers dictionary)
3. Remove unwanted log sources
4. Rebuild EXE using build script

---

## Service Management Commands

### Check Service Status
```powershell
Get-Service JFSSIEMAgent
```

### Start Service (from Command Prompt)
```
net start JFSSIEMAgent
```

### Stop Service (from Command Prompt)
```
net stop JFSSIEMAgent
```

### Remove Service (from Command Prompt)
```
sc delete JFSSIEMAgent
```

### View Service Logs
```
Get-EventLog -LogName System -Source JFSSIEMAgent -Newest 10
```

---

## Troubleshooting

### Problem: Service won't install
**Solution:**
1. Run Command Prompt as Administrator
2. Navigate to EXE folder
3. Run: `JFS_SIEM_Agent.exe install`

### Problem: Service won't start
**Solution:**
1. Check if collector is running and accessible
2. Verify firewall allows port 9999
3. Check Event Viewer for errors

### Problem: No events being collected
**Solution:**
1. Verify collector IP is correct
2. Test connection: `ping COLLECTOR_IP`
3. Check if Security event log has events
4. Verify user has admin rights

### Problem: Service stops after a while
**Solution:**
1. Check Event Viewer for errors
2. Verify network connectivity
3. Check collector is still running
4. Service should auto-restart (check logs)

---

## Advanced Configuration

### Change Collector IP Without Rebuilding
You can modify the running service by:
1. Stop the service: `net stop JFSSIEMAgent`
2. Edit `jfs_agent_service.py` in the same folder
3. Change line 52 to new IP
4. Rebuild EXE using the build script
5. Uninstall old service: `sc delete JFSSIEMAgent`
6. Install new version

### Enable Debug Logging
Edit `jfs_agent_service.py` line 28:
```python
level=logging.DEBUG,  # Change from INFO to DEBUG
```

Logs are saved to:
```
C:\Users\[USERNAME]\AppData\Local\JFS_SIEM_Agent\logs\jfs_agent_service.log
```

### Modify Event Collection Interval
Edit `jfs_agent_service.py` line 150 (in the run method):
```python
time.sleep(10)  # Change from 10 seconds to desired interval
```

---

## Deployment Checklist

- [ ] Copy EXE to target PC
- [ ] Double-click EXE to open GUI
- [ ] Verify collector IP is correct (default: 192.168.1.100)
- [ ] Click "Install Service"
- [ ] Click "Start Service"
- [ ] Verify service is running: `Get-Service JFSSIEMAgent`
- [ ] Check collector receives events
- [ ] Close EXE window
- [ ] Verify service still runs in background
- [ ] Reboot PC and verify service auto-starts

---

## Support

### Logs Location
```
%APPDATA%\JFS_SIEM_Agent\logs\jfs_agent_service.log
```

### Service Name
```
JFSSIEMAgent
```

### Default Settings
- Collector: `192.168.1.100:9999`
- Event Logs: System, Application, Security
- Startup: Automatic
- Account: LocalSystem

---

## Next Steps

1. **Deploy to target PC** - Copy EXE and run
2. **Install service** - Click "Install Service" button
3. **Start collecting** - Click "Start Service" button
4. **Verify in dashboard** - Check SIEM dashboard for events
5. **Monitor** - Check logs if issues occur

**That's it! Service will run 24/7 and survive reboots!** 🎉
