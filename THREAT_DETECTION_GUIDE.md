# JFS SIEM Threat Detection Engine - Complete Guide

## Overview

The Threat Detection Engine is a static, rule-based security alert system that analyzes normalized logs and generates structured security alerts. It requires no AI or machine learning - all detection is deterministic and based on predefined rules.

## Features

✅ **Static Rule-Based Detection** - No AI, fully deterministic
✅ **Critical Event Detection** - Log tampering, service installation, crashes
✅ **Brute-Force Detection** - 10+ failed logins in 5 minutes
✅ **Suspicious Process Detection** - cmd.exe, PowerShell execution
✅ **Privilege Escalation Detection** - Unauthorized admin access
✅ **Crash Correlation** - Service + application crash chains
✅ **Structured Alerts** - JSON format with recommendations
✅ **Severity Classification** - Low, Medium, High, Critical
✅ **Alert Management** - Status tracking, assignment, history
✅ **RESTful API** - Easy integration with other systems

## Installation

### Step 1: Create Database Tables

Visit: `http://localhost/SIEM/setup-threat-detection.php`

This creates three tables:
- `security_alerts` - Stores generated alerts
- `alert_rules` - Rule definitions
- `alert_history` - Audit trail of alert changes

### Step 2: Include in Your Application

```php
require_once 'includes/threat_detection.php';

$engine = new ThreatDetectionEngine($db);
```

## Detection Rules

### CRITICAL SEVERITY (Immediate Action Required)

#### Event ID 1102 - Security Logs Cleared
- **Title:** Security Logs Cleared
- **Severity:** CRITICAL
- **Category:** Log Tampering
- **Description:** Security event log has been cleared. This is a critical indicator of log tampering.
- **Recommended Actions:**
  - Immediately investigate who cleared the logs
  - Check for unauthorized access during the gap
  - Review backup logs if available
  - Enable log protection and immutability settings

#### Event ID 7045 - New Service Installed
- **Title:** New Service Installed
- **Severity:** CRITICAL
- **Category:** Persistence
- **Description:** A new service has been installed on the system. This could indicate malware persistence.
- **Recommended Actions:**
  - Verify the service is legitimate
  - Check service binary location and signature
  - Review service startup type and account
  - Scan binary with antivirus
  - Check for suspicious registry modifications

#### Event ID 7031 - Critical Service Crash
- **Title:** Critical Service Crash
- **Severity:** CRITICAL
- **Category:** Service Crash
- **Description:** A critical service has crashed unexpectedly.
- **Recommended Actions:**
  - Check service logs for error details
  - Verify system resources (CPU, memory, disk)
  - Check for recent updates or changes
  - Review application event log for related errors
  - Restart the service and monitor for recurrence

#### Event ID 1000 - Application Crash
- **Title:** Application Crash
- **Severity:** CRITICAL
- **Category:** Application Crash
- **Description:** An application has crashed unexpectedly.
- **Recommended Actions:**
  - Review application error details
  - Check for memory corruption or buffer overflow
  - Verify application is up to date
  - Check for hardware issues
  - Review recent changes to the system

#### Event ID 4697 - New Service Added (Possible Persistence)
- **Title:** New Service Added (Possible Persistence)
- **Severity:** CRITICAL
- **Category:** Persistence
- **Description:** A new service has been added to the system. This is a common malware persistence technique.
- **Recommended Actions:**
  - Verify service legitimacy immediately
  - Check service binary path and digital signature
  - Review service account and permissions
  - Scan binary with updated antivirus
  - Check for suspicious registry entries
  - Review process creation logs for service installation

#### Brute-Force Attack Detection
- **Title:** Brute-Force Login Attempt Detected
- **Severity:** CRITICAL
- **Category:** Brute Force
- **Trigger:** 10+ failed logins (Event ID 4625) within 5 minutes
- **Description:** Multiple failed login attempts detected from the same source.
- **Recommended Actions:**
  - Immediately check for successful intrusions
  - Review successful logins during and after attack
  - Enable account lockout policies
  - Implement IP-based blocking
  - Review and strengthen password policies
  - Enable MFA on critical accounts

### HIGH SEVERITY (Investigate Immediately)

#### Event ID 4688 - Process Execution
- **cmd.exe Execution**
  - **Title:** Suspicious Command Prompt Execution
  - **Severity:** HIGH
  - **Category:** Command Execution
  - **Recommended Actions:**
    - Review the parent process that launched cmd.exe
    - Check command line arguments
    - Verify the user account that executed it
    - Check for suspicious child processes
    - Review network connections made by cmd.exe

- **PowerShell Execution**
  - **Title:** Suspicious PowerShell Execution
  - **Severity:** HIGH
  - **Category:** Command Execution
  - **Recommended Actions:**
    - Review PowerShell command line arguments
    - Check parent process that launched PowerShell
    - Verify user account and privileges
    - Check for script block logging entries
    - Review network connections and file modifications

#### Event ID 4104 - PowerShell Script Block Logged
- **Title:** PowerShell Script Block Logged
- **Severity:** HIGH
- **Category:** Script Execution
- **Description:** PowerShell script block has been logged. Review for malicious content.
- **Recommended Actions:**
  - Analyze the PowerShell script content
  - Check for obfuscation or encoding
  - Verify script source and legitimacy
  - Review execution context and user
  - Check for network or file system modifications

#### Event ID 6008 - Unexpected System Shutdown
- **Title:** Unexpected System Shutdown
- **Severity:** HIGH
- **Category:** System Shutdown
- **Trigger:** Repeated (3+ times in 1 hour)
- **Description:** System has shut down unexpectedly.
- **Recommended Actions:**
  - Check system event log for shutdown reason
  - Review for power loss or hardware issues
  - Check for malware forcing shutdown
  - Verify recent system changes
  - Review security logs for suspicious activity before shutdown

### MEDIUM SEVERITY (Review and Verify)

#### Event ID 4720 - New User Account Created
- **Title:** New User Account Created
- **Severity:** MEDIUM
- **Category:** Account Management
- **Recommended Actions:**
  - Verify the account creation is authorized
  - Check account properties and group memberships
  - Review who created the account
  - Monitor the new account for suspicious activity
  - Verify account is needed for business purposes

#### Event ID 4728 - User Added to Group
- **Title:** User Added to Group
- **Severity:** MEDIUM
- **Category:** Privilege Change
- **Recommended Actions:**
  - Verify the group membership change is authorized
  - Check which group the user was added to
  - Review who made the change
  - Verify the user should have these permissions
  - Monitor for privilege escalation attempts

#### Event ID 4732 - User Added to Admin Group
- **Title:** User Added to Admin Group
- **Severity:** MEDIUM
- **Category:** Privilege Escalation
- **Recommended Actions:**
  - Verify the privilege escalation is authorized
  - Check if the user should have admin rights
  - Review who granted the privileges
  - Monitor the account for suspicious activity
  - Implement principle of least privilege

#### Repeated Application Crashes
- **Title:** Repeated Application Crashes Detected
- **Severity:** MEDIUM
- **Category:** Application Stability
- **Trigger:** 3+ crashes (Event ID 1000) within 30 minutes
- **Recommended Actions:**
  - Identify the crashing application
  - Check for memory leaks or resource issues
  - Verify application is properly installed
  - Check for hardware issues
  - Review recent system changes or updates

### LOW SEVERITY (Monitor)

#### Event ID 4624 - User Login
- **Title:** User Login
- **Severity:** LOW
- **Category:** Authentication
- **Recommended Actions:**
  - Monitor for unusual login patterns
  - Verify login location and time are expected
  - Check for concurrent sessions

#### Event ID 7036 - Service Status Changed
- **Title:** Service Status Changed
- **Severity:** LOW
- **Category:** Service Management
- **Recommended Actions:**
  - Verify the service status change is expected
  - Check service logs for details

#### Event ID 6005 - System Startup
- **Title:** System Startup
- **Severity:** LOW
- **Category:** System Event
- **Recommended Actions:**
  - Verify startup was expected
  - Check for unexpected services starting

#### Event ID 6006 - System Shutdown
- **Title:** System Shutdown
- **Severity:** LOW
- **Category:** System Event
- **Recommended Actions:**
  - Verify shutdown was expected

## API Reference

### Evaluate a Log

**Endpoint:** `POST /api/threat-detection.php?action=evaluate`

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
  "description": "Failed login attempt",
  "raw": "..."
}
```

**Response (Alert Generated):**
```json
{
  "success": true,
  "alert": {
    "alert_id": "ALERT_A1B2C3D4",
    "title": "Brute-Force Login Attempt Detected",
    "severity": "critical",
    "rule_id": "bruteforce",
    "matched_event_id": "4625",
    "timestamp": "2024-12-08 14:30:45",
    "category": "brute_force",
    "description": "10 or more failed login attempts detected within 5 minutes.",
    "details": {
      "computer": "WORKSTATION-01",
      "user": "admin",
      "source": "Security",
      "log_type": "Security",
      "failed_attempts": 10,
      "source_ip": "192.168.1.100",
      "target_user": "admin",
      "time_window": "5 minutes"
    },
    "recommended_actions": [
      "Immediately check for successful intrusions",
      "Review successful logins during and after attack",
      "Enable account lockout policies",
      "Implement IP-based blocking",
      "Review and strengthen password policies",
      "Enable MFA on critical accounts"
    ],
    "raw_log": { ... }
  }
}
```

**Response (No Alert):**
```json
{
  "success": true,
  "alert": null,
  "message": "No matching rules"
}
```

### Get All Alerts

**Endpoint:** `GET /api/threat-detection.php?action=get_alerts`

**Query Parameters:**
- `severity` - Filter by severity (low, medium, high, critical)
- `status` - Filter by status (new, acknowledged, resolved)
- `limit` - Number of results (default: 100)
- `offset` - Pagination offset (default: 0)

**Response:**
```json
{
  "success": true,
  "alerts": [ ... ],
  "total": 42,
  "limit": 100,
  "offset": 0
}
```

### Get Specific Alert

**Endpoint:** `GET /api/threat-detection.php?action=get_alert&alert_id=ALERT_A1B2C3D4`

**Response:**
```json
{
  "success": true,
  "alert": {
    "id": 1,
    "alert_id": "ALERT_A1B2C3D4",
    "title": "Brute-Force Login Attempt Detected",
    "severity": "critical",
    "status": "new",
    "timestamp": "2024-12-08 14:30:45",
    "details": { ... },
    "recommended_actions": [ ... ],
    "history": [
      {
        "id": 1,
        "alert_id": "ALERT_A1B2C3D4",
        "action": "Created",
        "user": "system",
        "timestamp": "2024-12-08 14:30:45",
        "notes": null
      }
    ]
  }
}
```

### Update Alert

**Endpoint:** `POST /api/threat-detection.php?action=update_alert`

**Request:**
```json
{
  "alert_id": "ALERT_A1B2C3D4",
  "status": "acknowledged",
  "assigned_to": "security_team",
  "notes": "Investigating brute-force attempt from 192.168.1.100"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Alert updated successfully"
}
```

### Get Alert Statistics

**Endpoint:** `GET /api/threat-detection.php?action=get_stats`

**Response:**
```json
{
  "success": true,
  "stats": {
    "total": 42,
    "by_severity": {
      "critical": 5,
      "high": 8,
      "medium": 15,
      "low": 14
    },
    "by_category": {
      "brute_force": 2,
      "persistence": 3,
      "command_execution": 5,
      "account_management": 8,
      ...
    }
  }
}
```

### Get Detection Rules

**Endpoint:** `GET /api/threat-detection.php?action=get_rules`

**Query Parameters:**
- `severity` - Filter by severity (low, medium, high, critical)
- `category` - Filter by category

**Response:**
```json
{
  "success": true,
  "rules": {
    "1102": {
      "title": "Security Logs Cleared",
      "severity": "critical",
      "category": "log_tampering",
      "description": "...",
      "recommended_actions": [ ... ]
    },
    ...
  },
  "count": 25
}
```

### Get Specific Rule

**Endpoint:** `GET /api/threat-detection.php?action=get_rule&rule_id=1102`

**Response:**
```json
{
  "success": true,
  "rule": {
    "title": "Security Logs Cleared",
    "severity": "critical",
    "category": "log_tampering",
    "description": "...",
    "recommended_actions": [ ... ]
  }
}
```

## Integration Examples

### PHP Integration

```php
require_once 'includes/threat_detection.php';

// Initialize engine
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
$engine = new ThreatDetectionEngine($db);

// Process a log
$log = [
    'timestamp' => '2024-12-08 14:30:45',
    'event_id' => '4625',
    'source' => 'Security',
    'log_type' => 'Security',
    'severity' => 'info',
    'computer' => 'WORKSTATION-01',
    'user' => 'admin',
    'source_ip' => '192.168.1.100',
    'description' => 'Failed login attempt',
    'raw' => '...'
];

$alert = $engine->evaluate_log($log);

if ($alert) {
    echo "Alert generated: " . $alert['title'];
    $engine->store_alert($alert);
} else {
    echo "No alert generated";
}
```

### JavaScript Integration

```javascript
// Evaluate a log
async function evaluateLog(log) {
    const response = await fetch('/SIEM/api/threat-detection.php?action=evaluate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(log)
    });
    
    const data = await response.json();
    
    if (data.alert) {
        console.log('Alert:', data.alert.title);
        displayAlert(data.alert);
    }
}

// Get all alerts
async function getAlerts(severity = null) {
    let url = '/SIEM/api/threat-detection.php?action=get_alerts';
    if (severity) {
        url += '&severity=' + severity;
    }
    
    const response = await fetch(url);
    const data = await response.json();
    
    return data.alerts;
}

// Update alert status
async function updateAlert(alertId, status, notes) {
    const response = await fetch('/SIEM/api/threat-detection.php?action=update_alert', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            alert_id: alertId,
            status: status,
            notes: notes
        })
    });
    
    return await response.json();
}
```

### Python Integration

```python
import requests
import json

# Evaluate a log
def evaluate_log(log):
    response = requests.post(
        'http://localhost/SIEM/api/threat-detection.php?action=evaluate',
        json=log
    )
    return response.json()

# Get alerts
def get_alerts(severity=None):
    url = 'http://localhost/SIEM/api/threat-detection.php?action=get_alerts'
    if severity:
        url += f'&severity={severity}'
    
    response = requests.get(url)
    return response.json()

# Update alert
def update_alert(alert_id, status, notes=None):
    response = requests.post(
        'http://localhost/SIEM/api/threat-detection.php?action=update_alert',
        json={
            'alert_id': alert_id,
            'status': status,
            'notes': notes
        }
    )
    return response.json()

# Example usage
log = {
    'timestamp': '2024-12-08 14:30:45',
    'event_id': '1102',
    'source': 'Security',
    'log_type': 'Security',
    'severity': 'critical',
    'computer': 'SERVER-01',
    'user': 'system',
    'description': 'Security logs cleared',
    'raw': '...'
}

result = evaluate_log(log)
if result['alert']:
    print(f"Alert: {result['alert']['title']}")
```

## Alert Lifecycle

1. **New** - Alert just generated
2. **Acknowledged** - Security team has reviewed
3. **Resolved** - Issue has been addressed

## Best Practices

1. **Monitor Critical Alerts** - Set up real-time notifications for critical severity alerts
2. **Regular Review** - Review and resolve alerts regularly
3. **Document Actions** - Add notes when updating alert status
4. **Assign Ownership** - Assign alerts to team members for investigation
5. **Correlation Analysis** - Look for patterns across multiple alerts
6. **Tune Rules** - Adjust rules based on your environment
7. **Backup Logs** - Maintain backup copies of security logs
8. **Test Regularly** - Test detection rules with sample events

## Troubleshooting

### Alerts Not Being Generated

1. Check that the database tables exist
2. Verify the log format matches expected input
3. Check PHP error logs for exceptions
4. Verify database connection is working

### False Positives

1. Review the matched rule
2. Check if the event is legitimate
3. Consider adjusting rule conditions
4. Document the false positive

### Performance Issues

1. Archive old alerts (older than 90 days)
2. Add database indexes on frequently queried columns
3. Limit alert retrieval with pagination
4. Consider implementing alert batching

## Files Created

- `includes/threat_detection.php` - Main detection engine
- `setup-threat-detection.php` - Database setup page
- `api/threat-detection.php` - RESTful API endpoint
- `THREAT_DETECTION_GUIDE.md` - This documentation

## Status

✅ **COMPLETE & PRODUCTION READY**

The threat detection engine is fully functional and ready for deployment.
