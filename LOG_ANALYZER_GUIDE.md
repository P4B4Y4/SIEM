# Rule-Based Log Analyzer - Complete Guide

## Overview

The Log Analyzer is a **rule-based classification and scoring system** that analyzes security logs in real-time. It uses **fixed, deterministic rules** (no AI) to:

- **Classify** logs into 6 categories
- **Score** severity from 1-10
- **Detect** anomalies
- **Generate** recommendations

## Features

✅ **6 Log Categories** - Authentication, Process, Network, File, System Error, Suspicious Activity
✅ **Severity Scoring** - 1-10 scale with keyword-based rules
✅ **Anomaly Detection** - Repeated events, unseen processes, rare ports, new IPs, system directory access
✅ **Smart Recommendations** - Category and severity-based action suggestions
✅ **RESTful API** - Easy integration with other systems
✅ **Batch Processing** - Analyze multiple logs at once
✅ **Database Integration** - Correlate with historical data

## Log Categories

### 1. Authentication
**Keywords:** login, logon, credential, token, authentication, NTLM, Kerberos, failed login, password, user account, access denied

**Examples:**
- User login attempts
- Failed authentication
- Password changes
- Token generation
- Account lockouts

### 2. Process Creation
**Keywords:** process, PID, cmd, command line, started, spawned, executable, launch, create process, image name, parent process

**Examples:**
- Process execution
- Command line execution
- Service startup
- Child process creation
- Executable launches

### 3. Network Connection
**Keywords:** connection, TCP, UDP, firewall, port, IP address, network, socket, DNS, HTTP, HTTPS, packet, source IP, destination, protocol

**Examples:**
- Network connections
- Firewall rules
- DNS queries
- Port usage
- Protocol activity

### 4. File Access
**Keywords:** file, read, write, delete, modified, .exe, .dll, directory, folder, path, access, permission, created, renamed, copied, moved

**Examples:**
- File read/write operations
- File deletion
- Directory access
- File modifications
- Permission changes

### 5. System Error
**Keywords:** error, warning, crash, failed, exception, fatal, critical, failure, fault, issue, problem, stopped, timeout

**Examples:**
- System crashes
- Service failures
- Critical errors
- Warnings
- Timeouts

### 6. Malware or Suspicious Activity
**Keywords:** powershell, base64, encoded, temp, unknown process, privilege, escalation, injection, shellcode, obfuscated, suspicious, malware, trojan, ransomware, backdoor, persistence, lateral movement

**Examples:**
- PowerShell execution
- Base64 encoding
- Privilege escalation
- Malware indicators
- Suspicious processes

## Severity Scoring (1-10)

### Severity 1-3: Normal Operations
- Routine system activity
- Expected operations
- No risk indicators

**Examples:**
- Normal user login
- System startup
- Service status change

### Severity 4-6: Suspicious Activity
- Failed login attempts
- Unusual IP addresses
- Repeated commands
- Access denied events

**Examples:**
- Multiple failed logins
- Unusual connection
- Repeated process execution

### Severity 7-8: High Risk
- Suspicious processes (PowerShell, cmd.exe)
- Base64 encoded commands
- Unexpected network connections
- System directory access

**Examples:**
- PowerShell script execution
- Encoded command line
- Rare port connection
- System file modification

### Severity 9-10: Critical
- Privilege escalation
- Persistence indicators
- Malware keywords
- Lateral movement

**Examples:**
- Privilege escalation attempt
- Service installation
- Malware detection
- Unauthorized admin access

## Anomaly Detection Rules

### Rule 1: Repeated Events
- **Trigger:** Event repeats > 5 times in 1 hour
- **Indicates:** Potential attack pattern or system issue
- **Action:** Investigate frequency and context

### Rule 2: Unseen Process
- **Trigger:** Process name never seen before
- **Indicates:** New or suspicious executable
- **Action:** Verify process legitimacy

### Rule 3: Rare Port
- **Trigger:** Port number > 50000
- **Indicates:** Non-standard port usage
- **Action:** Check firewall rules and destination

### Rule 4: New IP Login
- **Trigger:** User logs in from IP not seen in 30 days
- **Indicates:** Unusual access pattern
- **Action:** Verify user location and device

### Rule 5: System Directory Access
- **Trigger:** File write/delete in system directories
- **Indicates:** Potential malware or unauthorized change
- **Action:** Verify file integrity

## API Endpoints

### 1. Analyze Single Log

**Endpoint:** `POST /api/log-analyzer.php?action=analyze`

**Request:**
```json
{
  "timestamp": "2024-12-08 14:30:45",
  "event_id": "4625",
  "source": "Security",
  "log_type": "Security",
  "severity": "info",
  "computer": "WORKSTATION-01",
  "user": "admin",
  "source_ip": "192.168.1.100",
  "process_name": "powershell.exe",
  "description": "Failed login attempt",
  "raw": "..."
}
```

**Response:**
```json
{
  "success": true,
  "analysis": {
    "category": "Malware or Suspicious Activity",
    "severity": "8",
    "anomaly": "No",
    "reason": "PowerShell process execution; High severity - requires investigation",
    "recommendation": "Investigate the executable and its source; Check process parent and command line arguments; Review PowerShell script block logs; Escalate to SOC Level 2 for investigation"
  },
  "log": { ... }
}
```

### 2. Analyze Batch Logs

**Endpoint:** `POST /api/log-analyzer.php?action=analyze_batch`

**Request:**
```json
[
  {
    "timestamp": "2024-12-08 14:30:45",
    "event_id": "4625",
    ...
  },
  {
    "timestamp": "2024-12-08 14:31:00",
    "event_id": "4688",
    ...
  }
]
```

**Response:**
```json
{
  "success": true,
  "count": 2,
  "results": [
    {
      "log": { ... },
      "analysis": { ... }
    },
    {
      "log": { ... },
      "analysis": { ... }
    }
  ]
}
```

### 3. Get All Rules

**Endpoint:** `GET /api/log-analyzer.php?action=get_rules`

**Response:**
```json
{
  "success": true,
  "category_rules": {
    "Authentication": [...],
    "Process Creation": [...],
    ...
  },
  "severity_keywords": {
    "critical": [...],
    "high": [...],
    ...
  },
  "severity_scale": {
    "1-3": "Normal system operations...",
    ...
  },
  "anomaly_rules": {
    "repeated_event": "Event repeats more than 5 times",
    ...
  }
}
```

### 4. Analyze Stored Event

**Endpoint:** `GET /api/log-analyzer.php?action=analyze_event&event_id=123`

**Response:**
```json
{
  "success": true,
  "event_id": 123,
  "event": { ... },
  "analysis": {
    "category": "...",
    "severity": "...",
    "anomaly": "...",
    "reason": "...",
    "recommendation": "..."
  }
}
```

## Integration Examples

### PHP Integration

```php
require_once 'includes/log_analyzer.php';

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
$analyzer = new LogAnalyzer($db);

$log = [
    'timestamp' => '2024-12-08 14:30:45',
    'event_id' => '4688',
    'source' => 'Security',
    'log_type' => 'Security',
    'severity' => 'info',
    'computer' => 'WORKSTATION-01',
    'user' => 'admin',
    'process_name' => 'powershell.exe',
    'description' => 'PowerShell execution detected',
    'raw' => '...'
];

$analysis = $analyzer->analyze($log);

echo "Category: " . $analysis['category'] . "\n";
echo "Severity: " . $analysis['severity'] . "\n";
echo "Anomaly: " . $analysis['anomaly'] . "\n";
echo "Reason: " . $analysis['reason'] . "\n";
echo "Recommendation: " . $analysis['recommendation'] . "\n";
```

### JavaScript Integration

```javascript
// Analyze a single log
async function analyzeLog(log) {
    const response = await fetch('/SIEM/api/log-analyzer.php?action=analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(log)
    });
    
    const data = await response.json();
    console.log('Analysis:', data.analysis);
    return data.analysis;
}

// Analyze multiple logs
async function analyzeBatch(logs) {
    const response = await fetch('/SIEM/api/log-analyzer.php?action=analyze_batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(logs)
    });
    
    const data = await response.json();
    console.log(`Analyzed ${data.count} logs`);
    return data.results;
}

// Get all rules
async function getRules() {
    const response = await fetch('/SIEM/api/log-analyzer.php?action=get_rules');
    const data = await response.json();
    return data;
}
```

### Python Integration

```python
import requests
import json

# Analyze a log
def analyze_log(log):
    response = requests.post(
        'http://localhost/SIEM/api/log-analyzer.php?action=analyze',
        json=log
    )
    return response.json()

# Analyze batch
def analyze_batch(logs):
    response = requests.post(
        'http://localhost/SIEM/api/log-analyzer.php?action=analyze_batch',
        json=logs
    )
    return response.json()

# Get rules
def get_rules():
    response = requests.get(
        'http://localhost/SIEM/api/log-analyzer.php?action=get_rules'
    )
    return response.json()

# Example usage
log = {
    'timestamp': '2024-12-08 14:30:45',
    'event_id': '4625',
    'source': 'Security',
    'log_type': 'Security',
    'severity': 'info',
    'computer': 'WORKSTATION-01',
    'user': 'admin',
    'source_ip': '192.168.1.100',
    'description': 'Failed login attempt',
    'raw': '...'
}

result = analyze_log(log)
print(f"Category: {result['analysis']['category']}")
print(f"Severity: {result['analysis']['severity']}")
print(f"Anomaly: {result['analysis']['anomaly']}")
print(f"Recommendation: {result['analysis']['recommendation']}")
```

## Severity Mapping Examples

### Example 1: Failed Login (Severity 5)
```
Log: "Failed login attempt for admin from 192.168.1.100"

Analysis:
- Category: Authentication
- Severity: 5 (Medium)
- Anomaly: No
- Reason: Failed login attempt detected; Medium severity - monitor and verify
- Recommendation: Review authentication logs for failed attempts; Consider password reset if account compromised
```

### Example 2: PowerShell Execution (Severity 8)
```
Log: "Process created: powershell.exe with base64 encoded command"

Analysis:
- Category: Malware or Suspicious Activity
- Severity: 8 (High)
- Anomaly: Yes (unseen process)
- Reason: PowerShell process execution; Base64 encoding detected; High severity - requires investigation
- Recommendation: Investigate the executable and its source; Review PowerShell script block logs; Escalate to SOC Level 2
```

### Example 3: System File Modification (Severity 9)
```
Log: "File modified: C:\Windows\System32\drivers\etc\hosts"

Analysis:
- Category: File Access
- Severity: 9 (Critical)
- Anomaly: Yes (system directory access)
- Reason: System directory access; File modification in system directory; Critical severity - immediate escalation required
- Recommendation: Verify file integrity and permissions; Restore from backup if unauthorized modification; ESCALATE TO SOC LEVEL 2 IMMEDIATELY
```

## Best Practices

1. **Real-Time Analysis** - Analyze logs as they arrive
2. **Batch Processing** - Use batch endpoint for high volume
3. **Correlation** - Combine with threat detection engine
4. **Tuning** - Adjust rules based on your environment
5. **Escalation** - Automate SOC Level 2 escalation for critical severity
6. **Documentation** - Keep records of analysis decisions
7. **Testing** - Test rules with sample logs

## Troubleshooting

**Q: All logs getting low severity?**
A: Check keyword matching - ensure keywords are in the log text

**Q: Anomaly detection not working?**
A: Verify database connection and event history

**Q: Recommendations not specific enough?**
A: Add custom rules for your environment

## Files

- `includes/log_analyzer.php` - Core analyzer class
- `api/log-analyzer.php` - RESTful API endpoint
- `LOG_ANALYZER_GUIDE.md` - This documentation

## Status

✅ **COMPLETE & PRODUCTION READY**

The log analyzer is fully functional and ready for deployment.
