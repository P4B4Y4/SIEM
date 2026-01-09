# Deployment Instructions - v3.1.4

## Current Status

✅ **New EXE Built:** 223.9 MB
✅ **All Fixes Applied:** Command execution, error handling, deduplication
❌ **Old EXE Still Running:** Agent not executing new commands

## Problem

The **old EXE is still running** on the remote PC. It doesn't have the latest fixes, so new commands are not executing.

## Solution

Deploy the new EXE and restart the agent.

---

## Step-by-Step Deployment

### Step 1: Locate New EXE

**Location:**
```
D:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\dist\JFS_SIEM_Agent.exe
```

**Size:** 223.9 MB

### Step 2: Copy to Remote PC

Copy the new EXE to the remote PC where the agent is running.

**Example:**
```
From: D:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\dist\JFS_SIEM_Agent.exe
To:   C:\Program Files\JFS_SIEM_Agent\JFS_SIEM_Agent.exe
```

### Step 3: Stop Old Agent

**Option A: Via GUI**
1. Open the old EXE
2. Click "Stop Agent" button
3. Close the window

**Option B: Via Command Line**
```powershell
net stop JFSSIEMAgent
```

**Option C: Via Task Manager**
1. Open Task Manager
2. Find "JFS_SIEM_Agent.exe"
3. Right-click → End Task

### Step 4: Remove Old Service (if installed)

If the agent was installed as a Windows Service:

```powershell
sc delete JFSSIEMAgent
```

### Step 5: Run New EXE

Double-click the new EXE on the remote PC.

**Expected:**
- GUI window opens
- Shows configuration fields
- Shows: Collector IP, Port, PC Name

### Step 6: Configure (if needed)

Update configuration if server IP/port changed:
- **Collector IP:** Your SIEM server IP
- **Collector Port:** 80 (or configured port)
- **PC Name:** Auto-detected

### Step 7: Start Agent

Click "START AGENT" button.

**Expected:**
- Status changes to "Running"
- Events start being collected
- Agent connects to server

### Step 8: Install as Service (Optional)

If you want the agent to run 24/7:

1. Click "INSTALL SERVICE" button
2. Service installs successfully
3. Click "START SERVICE" button
4. Service starts running
5. Close the EXE window
6. Service continues running in background

### Step 9: Clear Old Pending Commands

Visit: `http://localhost/SIEM/clear-pending-commands.php?clear_all=1`

This clears any old stuck commands from the database.

### Step 10: Test Commands

1. Go to: `http://localhost/SIEM/pages/remote-terminal.php`
2. Select agent from sidebar
3. Send test command: `whoami`
4. **Expected:** Output appears immediately
5. Send: `lock`
6. **Expected:** Screen locks immediately

---

## Verification Checklist

- [ ] Old agent stopped
- [ ] New EXE copied to remote PC
- [ ] New EXE running
- [ ] Agent shows "Running" status
- [ ] Events being collected
- [ ] Old pending commands cleared
- [ ] New commands execute immediately
- [ ] Output displays in terminal

---

## Troubleshooting

### New Commands Still Not Executing

**Check:**
1. Is the new EXE running? (Check task manager)
2. Is the old EXE still running? (Stop it)
3. Is the agent connected? (Check events in database)
4. Is the server reachable? (Ping test)

**Solution:**
1. Stop all agent processes
2. Delete old EXE
3. Run new EXE
4. Test commands

### Agent Not Connecting

**Check:**
1. Collector IP correct?
2. Collector Port correct?
3. Firewall blocking?
4. Network connectivity?

**Solution:**
1. Verify server IP/port in agent config
2. Test connectivity: `ping server_ip`
3. Check firewall rules
4. Restart agent

### Commands Executing But Not Reporting

**Check:**
1. Agent can reach server?
2. API endpoint working?
3. Database accessible?

**Solution:**
1. Test API: `http://server/SIEM/api/remote-access.php?action=get_agents`
2. Check database connection
3. Check server logs

---

## Deployment Package

**Location:**
```
D:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\JFS_SIEM_Agent_Package\
```

**Contents:**
- `JFS_SIEM_Agent.exe` (223.9 MB) - Main executable
- `install.bat` - Batch installation script
- `install.ps1` - PowerShell installation script
- `README.txt` - Quick start guide

**Alternative Deployment:**
```powershell
# Copy entire folder to remote PC
Copy-Item -Path "JFS_SIEM_Agent_Package" -Destination "C:\Program Files\" -Recurse

# Run installation
cd "C:\Program Files\JFS_SIEM_Agent_Package"
.\install.bat install
.\install.bat start
```

---

## What's New in v3.1.4

✅ Fixed command execution reporting
✅ Fixed database update bug
✅ Improved error handling
✅ Fixed deduplication logic
✅ Better debugging information
✅ Timeout handling
✅ Response status checking

---

## Support

If deployment fails:

1. Check old agent is stopped
2. Verify new EXE is running
3. Check server connectivity
4. Review agent logs
5. Test API endpoints
6. Check database

---

## Summary

**Current Issue:** Old EXE still running, new commands not executing

**Solution:** Deploy new EXE and restart agent

**Expected Result:** New commands execute immediately

**Time to Deploy:** ~5 minutes

---

## Next Steps

1. ✅ Copy new EXE to remote PC
2. ✅ Stop old agent
3. ✅ Run new EXE
4. ✅ Test commands
5. ✅ Install as service (optional)

**Status:** Ready for deployment

