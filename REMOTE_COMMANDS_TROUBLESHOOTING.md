# Remote Commands Not Working - Troubleshooting Guide

## Problem
Remote features (lock, shutdown, restart, etc.) are not working. Commands are sent but not executed.

## Root Cause
The agent name used by the web interface might not match the agent name in the database, preventing the agent from retrieving pending commands.

## Solution Applied

### 1. Case-Insensitive Matching
Updated `get_pending_commands()` to match agent names case-insensitively:

```php
WHERE (agent_name = ? OR LOWER(agent_name) = LOWER(?)) AND status = 'pending'
```

This handles cases where:
- Web sends: "DESKTOP-ABC123"
- Database has: "desktop-abc123"
- Agent queries: "DESKTOP-ABC123"

### 2. Debug Endpoint Added
New debug endpoint to troubleshoot command retrieval:

```
GET /SIEM/api/remote-access.php?action=debug_commands&agent=AGENT_NAME
```

Returns:
- Commands found for agent
- All agent names in database
- Command details (id, status, timestamp)

---

## How to Troubleshoot

### Step 1: Check if Commands are in Database

Visit: `http://localhost/SIEM/api/remote-access.php?action=debug_commands&agent=DESKTOP-ABC123`

Replace `DESKTOP-ABC123` with your actual agent name.

Expected response:
```json
{
  "requested_agent": "DESKTOP-ABC123",
  "commands_found": 5,
  "commands": [
    {
      "id": 1,
      "agent_name": "DESKTOP-ABC123",
      "command": "lock",
      "status": "pending",
      "timestamp": "2025-12-09 16:20:00"
    }
  ],
  "all_agent_names_in_db": ["DESKTOP-ABC123", "LAPTOP-XYZ789"]
}
```

### Step 2: Verify Agent Name Match

Check that:
1. Agent name in web interface matches database
2. Agent is using correct PC name
3. No case sensitivity issues

### Step 3: Check Agent Configuration

On the agent PC:
1. Open EXE
2. Check "PC Name" field
3. Verify it matches the agent name in sidebar

### Step 4: Test Command Retrieval

Agent queries: `http://server:port/SIEM/api/remote-access.php?action=get_pending_commands&agent=DESKTOP-ABC123`

Should return pending commands.

---

## Common Issues & Solutions

### Issue 1: Commands Not Found
**Problem:** `commands_found: 0`

**Solution:**
1. Check agent name spelling
2. Verify command was sent (check web interface)
3. Check database has `remote_commands` table
4. Try case-insensitive match

### Issue 2: Agent Name Mismatch
**Problem:** Web shows "DESKTOP-ABC123" but database has "desktop-abc123"

**Solution:**
- Now fixed with case-insensitive matching
- Update agent PC name to match web interface

### Issue 3: Commands Stuck in Pending
**Problem:** Commands show status='pending' but never execute

**Solution:**
1. Verify agent is running
2. Check agent is polling for commands
3. Verify agent can reach server
4. Check firewall/network connectivity

### Issue 4: Agent Not Polling
**Problem:** Agent not checking for commands

**Solution:**
1. Verify `check_remote_commands()` thread is running
2. Check agent logs for errors
3. Verify server IP/port in agent config
4. Test connectivity: `ping server_ip`

---

## Testing Commands

### Test 1: Send Simple Command
1. Open remote terminal
2. Select agent
3. Send: `whoami`
4. Check if output appears

### Test 2: Send System Control Command
1. Send: `lock`
2. Check if screen locks
3. Check database for command status

### Test 3: Debug Command Retrieval
1. Send command via web
2. Visit debug endpoint
3. Verify command appears in response
4. Check agent receives it

---

## API Endpoints

### Send Command
```
POST /SIEM/api/remote-access.php?action=send_command&agent=AGENT_NAME
Body: {"command": "lock"}
```

### Get Pending Commands
```
GET /SIEM/api/remote-access.php?action=get_pending_commands&agent=AGENT_NAME
```

### Debug Commands
```
GET /SIEM/api/remote-access.php?action=debug_commands&agent=AGENT_NAME
```

### Report Command Result
```
POST /SIEM/api/remote-access.php?action=report_command&id=CMD_ID
Body: {"result": "success", "output": "...", "error": ""}
```

---

## Database Schema

### remote_commands Table
```sql
CREATE TABLE remote_commands (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_name VARCHAR(255),
    command LONGTEXT,
    status VARCHAR(50),
    result VARCHAR(50),
    output LONGTEXT,
    error LONGTEXT,
    timestamp DATETIME,
    completed_at DATETIME,
    INDEX(agent_name),
    INDEX(status)
);
```

---

## Agent Code Flow

```
1. Agent starts check_remote_commands() thread
2. Every 2 seconds:
   - Query: GET /api/remote-access.php?action=get_pending_commands&agent=PC_NAME
   - Receive: {"commands": [{id: 1, command: "lock"}]}
   - Execute: lock command in separate thread
   - Report: POST /api/remote-access.php?action=report_command&id=1
3. Web interface polls for results
4. Results displayed in terminal
```

---

## Verification Checklist

- [ ] Agent is running on remote PC
- [ ] Agent PC name matches web interface
- [ ] Commands appear in debug endpoint
- [ ] Agent can reach server (ping test)
- [ ] Firewall allows agent communication
- [ ] Database has remote_commands table
- [ ] Commands execute in separate thread
- [ ] Results reported back to server

---

## Quick Fix Checklist

If commands aren't working:

1. **Check Agent Name**
   ```
   Visit: http://localhost/SIEM/api/remote-access.php?action=debug_commands&agent=YOUR_PC_NAME
   ```

2. **Verify Command in Database**
   - Should see command in response
   - Status should be "pending"

3. **Check Agent Configuration**
   - PC Name should match
   - Server IP/Port should be correct

4. **Restart Agent**
   - Stop EXE
   - Start EXE
   - Try command again

5. **Check Logs**
   - Look for errors in agent
   - Check server logs for API errors

---

## Support

If commands still don't work:

1. Run debug endpoint
2. Share output
3. Check agent logs
4. Verify network connectivity
5. Verify database connectivity

---

## Version

- **Updated:** December 9, 2025
- **Fix:** Case-insensitive agent name matching
- **Status:** Ready for testing

