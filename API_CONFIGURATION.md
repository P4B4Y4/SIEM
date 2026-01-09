# JFS SIEM - API Configuration Guide

## Overview
Complete API configuration for JFS Security Operations Center (SOC) with support for Fortinet, ESET, threat detection, and system management.

## Configuration Files

### 1. config/config.php
Main PHP configuration file with all system constants and settings.

**Location:** `d:\xamp\htdocs\SIEM\config\config.php`

**Key Sections:**
- Organization Branding
- Database Configuration
- Security Team Contacts
- Compliance Settings
- ESET Configuration
- Fortinet Configuration
- Security Settings
- Alert & Notification Settings
- Threat Intelligence
- SOAR Settings
- Dashboard Settings
- API Configuration
- Backup & Disaster Recovery

### 2. config/settings.json
JSON-based settings file for runtime configuration changes.

**Location:** `d:\xamp\htdocs\SIEM\config\settings.json`

## API Endpoints

### Base URL
```
http://localhost/SIEM/api/
```

### Available Endpoints

#### 1. Settings API
**File:** `api/settings.php`
**Purpose:** Manage system settings programmatically

```
GET    /api/settings.php                          - Get all settings
GET    /api/settings.php?category=fortinet        - Get category settings
GET    /api/settings.php?category=fortinet&key=ip - Get specific setting
POST   /api/settings.php?category=fortinet        - Update settings
DELETE /api/settings.php?category=fortinet&key=ip - Delete setting
PATCH  /api/settings.php?action=test_database     - Test connection
```

#### 2. Events API
**File:** `api/events.php`
**Purpose:** Retrieve and manage security events

```
GET    /api/events.php                            - Get all events
GET    /api/events.php?filter=fortinet            - Filter by source
GET    /api/events.php?severity=critical          - Filter by severity
GET    /api/events.php?limit=100&offset=0         - Pagination
```

#### 3. Threat Detection API
**File:** `api/threat-detection.php`
**Purpose:** Evaluate logs and generate security alerts

```
POST   /api/threat-detection.php?action=evaluate  - Evaluate logs
GET    /api/threat-detection.php?action=get_alerts - Get alerts
GET    /api/threat-detection.php?action=get_alert&id=123 - Get specific alert
POST   /api/threat-detection.php?action=update_alert - Update alert status
GET    /api/threat-detection.php?action=get_stats - Get statistics
GET    /api/threat-detection.php?action=get_rules - Get detection rules
```

#### 4. Log Analyzer API
**File:** `api/log-analyzer.php`
**Purpose:** Analyze and parse logs from various sources

```
POST   /api/log-analyzer.php?action=analyze       - Analyze logs
GET    /api/log-analyzer.php?action=get_summary   - Get analysis summary
POST   /api/log-analyzer.php?action=parse         - Parse raw logs
```

#### 5. Agent Collector API
**File:** `api/agent-collector.php`
**Purpose:** Manage and collect data from remote agents

```
POST   /api/agent-collector.php?action=collect    - Trigger collection
GET    /api/agent-collector.php?action=status     - Get agent status
POST   /api/agent-collector.php?action=register   - Register new agent
```

#### 6. Alerting System API
**File:** `api/alerting-system.php`
**Purpose:** Create and manage security alerts

```
POST   /api/alerting-system.php?action=create     - Create alert
GET    /api/alerting-system.php?action=list       - List alerts
POST   /api/alerting-system.php?action=escalate   - Escalate alert
```

#### 7. Remote Access API
**File:** `api/remote-access.php`
**Purpose:** Execute remote commands and manage remote systems

```
POST   /api/remote-access.php?action=execute      - Execute command
GET    /api/remote-access.php?action=get_results  - Get command results
POST   /api/remote-access.php?action=send_command - Send remote command
```

#### 8. Email Alert API
**File:** `api/send-alert-email.php`
**Purpose:** Send email notifications for security events

```
POST   /api/send-alert-email.php                  - Send alert email
POST   /api/send-alert-email.php?action=test      - Test email configuration
```

## Configuration Details

### Database Configuration
```php
DB_HOST: localhost
DB_NAME: jfs_siem
DB_USER: root
DB_PASS: (empty - set your password)
DB_PORT: 3306
DB_CHARSET: utf8mb4
```

### Fortinet Configuration
```php
FORTINET_ENABLED: true
FORTINET_IP: 192.168.1.99
FORTINET_API_KEY: hQx5kfknbm8z6h831HhrzG5Hrf4Hrc
FORTINET_SYSLOG_PORT: 514
FORTINET_LOG_METHOD: syslog (or api)
```

### ESET Configuration
```php
ESET_ENABLED: true
ESET_SERVER_IP: us02.protect.eset.com
ESET_SYSLOG_PORT: 6514
ESET_LOG_PATH: C:\ProgramData\ESET\RemoteAdministrator\Server\Logs
```

### SMTP Configuration
```php
SMTP_HOST: smtp.office365.com
SMTP_PORT: 587
SMTP_USERNAME: security.ict@jfsholdings.com
SMTP_PASSWORD: (empty - set your password)
SMTP_ENCRYPTION: tls
SMTP_FROM_EMAIL: security.ict@jfsholdings.com
SMTP_FROM_NAME: JFS Security Operations Center
```

### Security Settings
```php
SESSION_TIMEOUT: 1800 (30 minutes)
PASSWORD_MIN_LENGTH: 12
MAX_LOGIN_ATTEMPTS: 3
LOCKOUT_DURATION: 1800 (30 minutes)
ENABLE_2FA: false
```

### API Settings
```php
ENABLE_API: true
API_RATE_LIMIT: 100 (requests per minute)
ENABLE_WEBHOOK: true
WEBHOOK_SECRET: (set a strong secret)
```

### Dashboard Settings
```php
DASHBOARD_REFRESH_INTERVAL: 30 (seconds)
MAX_DASHBOARD_EVENTS: 50
DASHBOARD_THEME: professional
SHOW_REAL_TIME_EVENTS: true
SHOW_GEOGRAPHIC_MAP: true
SHOW_THREAT_TRENDS: true
SHOW_COMPLIANCE_STATUS: true
```

## API Authentication

### Session-Based Authentication
Most endpoints require admin login via session:

```php
// Check if authenticated
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('HTTP/1.1 403 Forbidden');
    exit(json_encode(['error' => 'Unauthorized']));
}
```

### API Key Authentication (Optional)
For programmatic access, implement API key header:

```php
$api_key = $_SERVER['HTTP_X_JFS_API_KEY'] ?? '';
if ($api_key !== WEBHOOK_SECRET) {
    header('HTTP/1.1 401 Unauthorized');
    exit(json_encode(['error' => 'Invalid API Key']));
}
```

## Response Format

All API endpoints return JSON:

```json
{
  "success": true,
  "message": "Operation successful",
  "data": {
    "key": "value"
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message",
  "code": 400
}
```

## Common Use Cases

### 1. Get Fortinet Configuration
```bash
curl -X GET "http://localhost/SIEM/api/settings.php?category=fortinet" \
  -b "PHPSESSID=your_session_id"
```

### 2. Update Fortinet IP
```bash
curl -X POST "http://localhost/SIEM/api/settings.php?category=fortinet&key=ip" \
  -H "Content-Type: application/json" \
  -d '{"value": "192.168.1.100"}' \
  -b "PHPSESSID=your_session_id"
```

### 3. Evaluate Logs for Threats
```bash
curl -X POST "http://localhost/SIEM/api/threat-detection.php?action=evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "Fortinet-Traffic-Deny",
    "severity": "high",
    "source_ip": "192.168.1.50",
    "destination_ip": "8.8.8.8"
  }' \
  -b "PHPSESSID=your_session_id"
```

### 4. Get Recent Alerts
```bash
curl -X GET "http://localhost/SIEM/api/threat-detection.php?action=get_alerts&limit=10" \
  -b "PHPSESSID=your_session_id"
```

### 5. Test Database Connection
```bash
curl -X PATCH "http://localhost/SIEM/api/settings.php?action=test_database" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "localhost",
    "user": "root",
    "pass": "",
    "name": "jfs_siem"
  }' \
  -b "PHPSESSID=your_session_id"
```

## Security Considerations

1. **Always use HTTPS in production** - Set `session.cookie_secure` to 1
2. **Protect API Keys** - Store in environment variables, not in code
3. **Rate Limiting** - API_RATE_LIMIT is set to 100 requests/minute
4. **Input Validation** - All inputs are validated server-side
5. **Session Security** - HTTPOnly cookies, Strict SameSite policy
6. **CORS** - Configure CORS headers for cross-domain requests

## Compliance

- **ISO 27001:2013** - Primary compliance framework
- **Data Retention** - 365 days (configurable)
- **Audit Logging** - All API calls logged for compliance
- **Incident Response** - Automated response for critical events

## Troubleshooting

### 403 Forbidden
- Ensure you're logged in with admin role
- Check session cookies are being sent
- Verify PHPSESSID is valid

### 400 Bad Request
- Check required parameters are provided
- Verify JSON syntax in request body
- Ensure Content-Type header is set to application/json

### 500 Server Error
- Check PHP error logs in `logs/` directory
- Verify database connection
- Check file permissions on config files

## Support & Documentation

- **Settings API:** See `API_SETTINGS_DOCS.md`
- **Threat Detection:** See `THREAT_DETECTION_GUIDE.md`
- **Log Analysis:** See `LOG_ANALYZER_GUIDE.md`
- **Alerting:** See `ALERTING_SYSTEM_GUIDE.md`

## Status

✅ **API Configuration Complete**
- All endpoints configured
- Database connected
- Fortinet integration ready
- ESET integration ready
- Threat detection enabled
- Email alerts configured

**Last Updated:** December 9, 2025
**Version:** 1.0.0
