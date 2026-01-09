# SIEM Remote Access Feature

## Overview

The SIEM system now includes **Remote Access Control** - similar to AnyDesk or TeamViewer. Admins can control remote PCs directly from the web dashboard.

---

## How It Works

### 1. Dashboard Integration
```
Dashboard → Events Table → Click "🖥️ Remote Access" → Control Panel Opens
```

### 2. Remote Control Interface
```
┌─────────────────────────────────────────────┐
│ Remote Access Control                       │
├──────────────┬──────────────────────────────┤
│ Agents       │ Remote Screen                │
│ • PC-1       │ 📺 Remote Display            │
│ • PC-2       │                              │
│ • PC-3       │                              │
├──────────────┴──────────────────────────────┤
│ Controls: Screenshot | Ctrl+Alt+Del | Lock │
│          | Restart | Shutdown | Execute    │
└─────────────────────────────────────────────┘
```

---

## Features

### Control Options

| Feature | Description | Command |
|---------|-------------|---------|
| **Screenshot** | Capture remote screen | `screenshot` |
| **Ctrl+Alt+Del** | Send Ctrl+Alt+Del | `ctrl+alt+del` |
| **Lock Screen** | Lock remote PC | `lock` |
| **Restart** | Restart remote PC | `restart` |
| **Shutdown** | Shutdown remote PC | `shutdown` |
| **Execute** | Run custom command | `custom command` |

### Agent List
- Shows all connected agents
- Displays online/offline status
- Shows event count
- Last seen timestamp

---

## Usage

### Step 1: Open Dashboard
```
http://localhost/SIEM/pages/dashboard_working.php
```

### Step 2: Find Agent
```
Look at Recent Events table
Find the PC you want to control
```

### Step 3: Click Remote Access
```
Click "🖥️ Remote Access" button
Remote control panel opens
```

### Step 4: Control PC
```
Select agent from sidebar
Use control buttons
Execute commands
```

---

## API Endpoints

### Get Agents
```
GET /SIEM/api/remote-access.php?action=get_agents
```
Returns list of all connected agents.

### Get Agent Details
```
GET /SIEM/api/remote-access.php?action=get_agent_details&agent=PC-NAME
```
Returns detailed info about specific agent.

### Send Command
```
POST /SIEM/api/remote-access.php?action=send_command&agent=PC-NAME
Body: {"command": "command_name"}
```
Sends command to agent.

### Get Screenshot
```
GET /SIEM/api/remote-access.php?action=get_screen&agent=PC-NAME
```
Requests screenshot from agent.

### Mouse Control
```
POST /SIEM/api/remote-access.php?action=mouse_move&agent=PC-NAME
Body: {"x": 100, "y": 200}

POST /SIEM/api/remote-access.php?action=mouse_click&agent=PC-NAME
Body: {"button": "left", "x": 100, "y": 200}
```

### Keyboard Input
```
POST /SIEM/api/remote-access.php?action=keyboard_input&agent=PC-NAME
Body: {"keys": "hello world"}
```

---

## Agent Requirements

For full remote access support, agents need to:

1. **Support Screenshots**
   - Capture screen and send to server
   - Store in database

2. **Support Commands**
   - Receive commands from server
   - Execute and return results

3. **Support Input**
   - Mouse movement/clicks
   - Keyboard input
   - Ctrl+Alt+Del, Lock, Restart, Shutdown

---

## Current Implementation

### Supported
- ✅ Agent list and status
- ✅ Agent details
- ✅ Command sending
- ✅ Mouse/keyboard control API
- ✅ Web interface

### Requires Agent Enhancement
- ⏳ Screenshot capture
- ⏳ Command execution
- ⏳ Input handling

---

## Database Tables

### remote_commands
```sql
CREATE TABLE remote_commands (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_name VARCHAR(255),
    command TEXT,
    timestamp DATETIME,
    status VARCHAR(50),
    result TEXT
);
```

---

## Security Considerations

⚠️ **Important:**
- Only authenticated users can access remote control
- All commands are logged
- Sensitive operations require confirmation
- Consider adding IP whitelisting
- Use HTTPS in production

---

## Future Enhancements

1. **Real-time Screenshots**
   - Live screen streaming
   - Compression for bandwidth

2. **File Transfer**
   - Upload/download files
   - Batch operations

3. **Process Management**
   - View running processes
   - Kill processes
   - Start applications

4. **Registry Access**
   - View/modify registry
   - Export settings

5. **Advanced Logging**
   - Record all actions
   - Audit trail
   - Session playback

---

## Troubleshooting

**No agents showing:**
- Verify agents are running
- Check database connection
- Verify events are being collected

**Commands not executing:**
- Agent may not support command execution yet
- Check agent logs
- Verify network connectivity

**Screenshot not loading:**
- Agent screenshot support not implemented
- Check agent version
- Verify database storage

---

**JFS ICT Services - Professional Remote Access Management**
