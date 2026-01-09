# Threat Detection Engine - Quick Start (5 Minutes)

## Installation

### Step 1: Create Database Tables (1 minute)

1. Open browser: `http://localhost/SIEM/setup-threat-detection.php`
2. Click **"Create Database Tables"**
3. Wait for success message
4. ✅ Done!

## Usage

### Option A: Using the API (Recommended)

**Send a log for evaluation:**

```bash
curl -X POST http://localhost/SIEM/api/threat-detection.php?action=evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-12-08 14:30:45",
    "event_id": "4625",
    "source": "Security",
    "log_type": "Security",
    "severity": "info",
    "computer": "WORKSTATION-01",
    "user": "admin",
    "source_ip": "192.168.1.100",
    "description": "Failed login attempt",
    "raw": "..."
  }'
```

**Get all alerts:**

```bash
curl http://localhost/SIEM/api/threat-detection.php?action=get_alerts
```

**Get critical alerts only:**

```bash
curl http://localhost/SIEM/api/threat-detection.php?action=get_alerts&severity=critical
```

**Update alert status:**

```bash
curl -X POST http://localhost/SIEM/api/threat-detection.php?action=update_alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "ALERT_A1B2C3D4",
    "status": "acknowledged",
    "notes": "Investigating..."
  }'
```

### Option B: Using PHP

```php
require_once 'includes/threat_detection.php';

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
$engine = new ThreatDetectionEngine($db);

// Evaluate a log
$log = [
    'timestamp' => '2024-12-08 14:30:45',
    'event_id' => '1102',
    'source' => 'Security',
    'log_type' => 'Security',
    'severity' => 'critical',
    'computer' => 'SERVER-01',
    'user' => 'system',
    'description' => 'Security logs cleared',
    'raw' => '...'
];

$alert = $engine->evaluate_log($log);

if ($alert) {
    echo "Alert: " . $alert['title'] . "\n";
    echo "Severity: " . $alert['severity'] . "\n";
    echo "Actions: " . implode(", ", $alert['recommended_actions']) . "\n";
    
    // Store in database
    $engine->store_alert($alert);
}
```

### Option C: Using JavaScript

```javascript
// Evaluate a log
async function checkLog(log) {
    const response = await fetch('/SIEM/api/threat-detection.php?action=evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(log)
    });
    
    const data = await response.json();
    
    if (data.alert) {
        console.log('🚨 Alert:', data.alert.title);
        console.log('Severity:', data.alert.severity);
        console.log('Actions:', data.alert.recommended_actions);
    }
}

// Get all critical alerts
async function getCriticalAlerts() {
    const response = await fetch('/SIEM/api/threat-detection.php?action=get_alerts&severity=critical');
    const data = await response.json();
    
    console.log(`Found ${data.total} critical alerts`);
    data.alerts.forEach(alert => {
        console.log(`- ${alert.title} (${alert.alert_id})`);
    });
}
```

## Common Detection Scenarios

### Scenario 1: Brute-Force Attack

**What triggers it:**
- 10+ failed login attempts (Event ID 4625) from same source within 5 minutes

**Alert generated:**
```
Title: Brute-Force Login Attempt Detected
Severity: CRITICAL
Actions:
  - Immediately check for successful intrusions
  - Enable account lockout policies
  - Implement IP-based blocking
  - Enable MFA on critical accounts
```

### Scenario 2: Service Installation

**What triggers it:**
- Event ID 7045 or 4697 (new service added)

**Alert generated:**
```
Title: New Service Installed
Severity: CRITICAL
Actions:
  - Verify service legitimacy
  - Check binary signature
  - Scan with antivirus
  - Check for suspicious registry entries
```

### Scenario 3: Suspicious Command Execution

**What triggers it:**
- Event ID 4688 with cmd.exe or powershell.exe

**Alert generated:**
```
Title: Suspicious PowerShell Execution
Severity: HIGH
Actions:
  - Review command line arguments
  - Check parent process
  - Review network connections
  - Check for file modifications
```

### Scenario 4: Log Tampering

**What triggers it:**
- Event ID 1102 (security logs cleared)

**Alert generated:**
```
Title: Security Logs Cleared
Severity: CRITICAL
Actions:
  - Investigate who cleared logs
  - Check for unauthorized access
  - Review backup logs
  - Enable log protection
```

## Testing the Engine

### Test 1: Generate a Critical Alert

```bash
curl -X POST http://localhost/SIEM/api/threat-detection.php?action=evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-12-08 14:30:45",
    "event_id": "1102",
    "source": "Security",
    "log_type": "Security",
    "severity": "critical",
    "computer": "SERVER-01",
    "user": "system",
    "description": "Security logs cleared",
    "raw": "Event 1102"
  }'
```

**Expected Response:**
```json
{
  "success": true,
  "alert": {
    "alert_id": "ALERT_...",
    "title": "Security Logs Cleared",
    "severity": "critical",
    "rule_id": "1102",
    ...
  }
}
```

### Test 2: Trigger Brute-Force Detection

Send 10+ failed login events from the same IP:

```bash
for i in {1..10}; do
  curl -X POST http://localhost/SIEM/api/threat-detection.php?action=evaluate \
    -H "Content-Type: application/json" \
    -d '{
      "timestamp": "2024-12-08 14:30:'$(printf "%02d" $i)'",
      "event_id": "4625",
      "source": "Security",
      "log_type": "Security",
      "severity": "info",
      "computer": "WORKSTATION-01",
      "user": "admin",
      "source_ip": "192.168.1.100",
      "description": "Failed login",
      "raw": "..."
    }'
done
```

### Test 3: View Generated Alerts

```bash
curl http://localhost/SIEM/api/threat-detection.php?action=get_alerts
```

## Alert Status Workflow

```
┌─────────────────────────────────────────┐
│  Alert Generated (Status: NEW)           │
│  - Timestamp recorded                    │
│  - Rule matched                          │
│  - Recommendations provided              │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│  Security Team Reviews (Status: NEW)     │
│  - Check alert details                   │
│  - Review recommended actions            │
│  - Assign to team member                 │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│  Team Acknowledges (Status: ACKNOWLEDGED)│
│  - Investigating the issue               │
│  - Add notes and findings                │
│  - Update assignment if needed           │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│  Issue Resolved (Status: RESOLVED)       │
│  - Document resolution                   │
│  - Add final notes                       │
│  - Close alert                           │
└─────────────────────────────────────────┘
```

## Detection Rules Summary

| Event ID | Title | Severity | Category |
|----------|-------|----------|----------|
| 1102 | Security Logs Cleared | CRITICAL | Log Tampering |
| 7045 | New Service Installed | CRITICAL | Persistence |
| 7031 | Critical Service Crash | CRITICAL | Service Crash |
| 1000 | Application Crash | CRITICAL | App Crash |
| 4697 | New Service Added | CRITICAL | Persistence |
| bruteforce | Brute-Force Attempt | CRITICAL | Brute Force |
| 4688_cmd | cmd.exe Execution | HIGH | Command Exec |
| 4688_powershell | PowerShell Execution | HIGH | Command Exec |
| 4104 | PowerShell Script Block | HIGH | Script Exec |
| 6008 | Unexpected Shutdown | HIGH | System Shutdown |
| 4720 | New User Account | MEDIUM | Account Mgmt |
| 4728 | User Added to Group | MEDIUM | Privilege Change |
| 4732 | User Added to Admin | MEDIUM | Privilege Escalation |
| repeated_crashes | Repeated Crashes | MEDIUM | App Stability |
| 4624 | User Login | LOW | Authentication |
| 7036 | Service Status Changed | LOW | Service Mgmt |
| 6005 | System Startup | LOW | System Event |
| 6006 | System Shutdown | LOW | System Event |

## Key Features

✅ **25+ Detection Rules** - Covers critical security events
✅ **Temporal Correlation** - Detects patterns over time
✅ **Structured Alerts** - JSON format with recommendations
✅ **RESTful API** - Easy integration
✅ **Alert Management** - Track status and history
✅ **No AI Required** - Static, deterministic rules
✅ **Production Ready** - Fully tested and documented

## Troubleshooting

**Q: No alerts being generated?**
A: Check that database tables exist and log format is correct

**Q: Getting false positives?**
A: Review the matched rule and verify the event is legitimate

**Q: API returning errors?**
A: Check PHP error logs and verify database connection

## Next Steps

1. ✅ Run setup-threat-detection.php
2. ✅ Test with sample logs
3. ✅ Integrate with your log pipeline
4. ✅ Monitor alerts in dashboard
5. ✅ Tune rules for your environment

## Documentation

- **Full Guide:** `THREAT_DETECTION_GUIDE.md`
- **Summary:** `THREAT_DETECTION_SUMMARY.txt`
- **API Reference:** See THREAT_DETECTION_GUIDE.md
- **Code:** `includes/threat_detection.php`

---

**Status:** ✅ Ready to use!

Start evaluating logs now and generate security alerts.
