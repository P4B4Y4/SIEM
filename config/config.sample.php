<?php
/**
 * JFS ICT Services (PVT) LTD - SIEM Configuration (Sample)
 *
 * Copy this file to config.local.php and fill in your real values.
 * config.local.php must NOT be committed.
 */

// ============================================
// ORGANIZATION BRANDING
// ============================================
define('ORG_NAME', 'JFS ICT Services (PVT) LTD');
define('ORG_SHORT_NAME', 'JFS ICT');
define('ORG_LOGO_PATH', 'assets/images/jfs-logo.png');
define('ORG_DOMAIN', 'jfsholdings.com');
define('ORG_PRIMARY_COLOR', '#000080');
define('ORG_SECONDARY_COLOR', '#0000CD');
define('ORG_ACCENT_COLOR', '#4169E1');
define('ORG_TEXT_ON_PRIMARY', '#FFFFFF');

// Application Settings
define('APP_NAME', 'JFS Security Operations Center');
define('APP_SHORT_NAME', 'JFS SOC');
define('APP_VERSION', '1.0.0');
define('APP_ENVIRONMENT', 'production');
define('APP_URL', 'http://localhost/SIEM');
define('TIMEZONE', 'Asia/Colombo');

// ============================================
// DATABASE CONFIGURATION
// ============================================
define('DB_HOST', 'localhost');
define('DB_NAME', 'jfs_siem');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_PORT', 3306);
define('DB_CHARSET', 'utf8mb4');

// ============================================
// SECURITY TEAM CONTACTS
// ============================================
define('SECURITY_EMAIL', 'security.ict@jfsholdings.com');
define('SECURITY_PHONE', '+94-XX-XXXXXXX');
define('INCIDENT_RESPONSE_EMAIL', 'security.ict@jfsholdings.com');
define('SOC_MANAGER_EMAIL', 'soc.manager@jfsholdings.com');

// ============================================
// COMPLIANCE SETTINGS
// ============================================
define('PRIMARY_COMPLIANCE', 'ISO 27001:2013');
define('ENABLE_ISO27001_REPORTS', true);
define('ENABLE_AUDIT_LOGGING', true);
define('DATA_RETENTION_DAYS', 365);
define('AUDIT_LOG_RETENTION_DAYS', 730);

// ============================================
// ESET ENDPOINT PROTECTION CONFIGURATION
// ============================================
define('ESET_ENABLED', true);
define('ESET_PRODUCT', 'ESET Endpoint Security');
define('ESET_MANAGEMENT', 'ESET Security Management Center');
define('ESET_VERSION', '10.x');
define('ESET_SERVER_IP', 'us02.protect.eset.com');
define('ESET_LOG_PATH', 'C:\\ProgramData\\ESET\\RemoteAdministrator\\Server\\Logs');
define('ESET_SYSLOG_PORT', '5514');

define('ESET_CRITICAL_EVENTS', [
    'Virus detected',
    'Malware detected',
    'Ransomware detected',
    'Real-time protection disabled',
    'Firewall disabled'
]);

define('ESET_HIGH_EVENTS', [
    'Potentially unwanted application',
    'Suspicious file',
    'Web threat blocked',
    'Email threat blocked'
]);

// ============================================
// FORTINET FORTIGATE CONFIGURATION
// ============================================
define('FORTINET_ENABLED', true);
define('FORTINET_PRODUCT', 'FortiGate');
define('FORTINET_IP', '192.168.1.99');
define('FORTINET_API_KEY', '');
define('FORTINET_SYSLOG_PORT', '514');
define('FORTINET_LOG_METHOD', 'syslog');

define('FORTINET_CRITICAL_EVENTS', [
    'IPS signature detected',
    'DoS attack detected',
    'Botnet activity',
    'Critical vulnerability exploit'
]);

define('FORTINET_HIGH_EVENTS', [
    'Multiple failed VPN attempts',
    'Suspicious outbound connection',
    'High bandwidth usage',
    'Geo-blocking violation'
]);

// ============================================
// SECURITY SETTINGS
// ============================================
define('SESSION_TIMEOUT', 1800);
define('PASSWORD_MIN_LENGTH', 12);
define('PASSWORD_REQUIRE_SPECIAL', true);
define('PASSWORD_REQUIRE_NUMBER', true);
define('PASSWORD_REQUIRE_UPPERCASE', true);
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_DURATION', 1800);
define('ENABLE_2FA', false);

// ============================================
// ALERT & NOTIFICATION SETTINGS
// ============================================
define('ALERT_RETENTION_DAYS', 90);
define('EVENT_RETENTION_DAYS', 365);
define('MAX_EVENTS_PER_PAGE', 100);

define('AUTO_ALERT_CRITICAL', true);
define('AUTO_ALERT_HIGH', true);
define('AUTO_ALERT_MEDIUM', false);
define('ALERT_BATCH_INTERVAL', 300);

// Email Notification Settings
define('SMTP_HOST', 'smtp.office365.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', '');
define('SMTP_PASSWORD', '');
define('SMTP_ENCRYPTION', 'tls');
define('SMTP_FROM_EMAIL', '');
define('SMTP_FROM_NAME', 'JFS Security Operations Center');

// SMS Notification (Optional)
define('ENABLE_SMS_ALERTS', false);
define('SMS_API_PROVIDER', 'twilio');
define('SMS_API_KEY', '');
define('SMS_ALERT_NUMBERS', ['+94-XX-XXXXXXX']);

// ============================================
// THREAT INTELLIGENCE SETTINGS
// ============================================
define('ENABLE_THREAT_INTEL', true);
define('THREAT_INTEL_UPDATE_INTERVAL', 3600);
define('ENABLE_IP_REPUTATION', true);
define('ENABLE_FILE_REPUTATION', true);

define('VIRUSTOTAL_API_KEY', '');
define('ABUSEIPDB_API_KEY', '');
define('ALIENVAULT_API_KEY', '');

// ============================================
// SOAR (Security Orchestration & Automation)
// ============================================
define('ENABLE_AUTOMATED_RESPONSE', true);
define('ENABLE_AUTO_IP_BLOCKING', true);
define('ENABLE_AUTO_ACCOUNT_LOCKOUT', true);
define('ENABLE_AUTO_QUARANTINE', true);
define('AUTO_RESPONSE_CRITICAL_ONLY', true);

define('CRITICAL_RESPONSE_TIME', 15);
define('HIGH_RESPONSE_TIME', 60);
define('MEDIUM_RESPONSE_TIME', 240);
define('LOW_RESPONSE_TIME', 1440);

// ============================================
// DASHBOARD SETTINGS
// ============================================
define('DASHBOARD_REFRESH_INTERVAL', 30);
define('SHOW_REAL_TIME_EVENTS', true);
define('MAX_DASHBOARD_EVENTS', 50);
define('DASHBOARD_THEME', 'professional');
define('SHOW_GEOGRAPHIC_MAP', true);
define('SHOW_THREAT_TRENDS', true);
define('SHOW_COMPLIANCE_STATUS', true);

define('DASHBOARD_WIDGETS', [
    'critical_alerts' => true,
    'eset_status' => true,
    'fortinet_status' => true,
    'threat_intelligence' => true,
    'compliance_score' => true,
    'agent_health' => true,
    'recent_incidents' => true,
    'top_threats' => true
]);

// ============================================
// LOGGING & DEBUGGING
// ============================================
define('ENABLE_DEBUG_LOG', true);
define('LOG_DIR', __DIR__ . '/../logs/');
define('LOG_LEVEL', 'INFO');
define('ENABLE_SYSLOG', true);
define('SYSLOG_SERVER', '127.0.0.1');

// ============================================
// PERFORMANCE SETTINGS
// ============================================
define('ENABLE_CACHING', true);
define('CACHE_TIMEOUT', 300);
define('MAX_EVENTS_PER_SECOND', 10000);
define('DATABASE_QUERY_TIMEOUT', 30);
define('ENABLE_QUERY_OPTIMIZATION', true);

// ============================================
// INTEGRATION ENDPOINTS
// ============================================
define('ENABLE_API', true);
define('API_KEY_HEADER', 'X-JFS-API-Key');
define('API_RATE_LIMIT', 100);
define('ENABLE_WEBHOOK', true);
define('WEBHOOK_SECRET', '');

// ============================================
// BACKUP & DISASTER RECOVERY
// ============================================
define('ENABLE_AUTO_BACKUP', true);
define('BACKUP_FREQUENCY', 'daily');
define('BACKUP_RETENTION_DAYS', 90);
define('BACKUP_PATH', 'C:\\JFS-SIEM-Backups');

// ============================================
// APPLICATION URLS
// ============================================
define('BASE_URL', 'http://localhost/SIEM/');
define('LOGIN_URL', BASE_URL . 'pages/login.php');
define('DASHBOARD_URL', BASE_URL . 'pages/dashboard.php');
define('LOGOUT_URL', BASE_URL . 'pages/logout.php');

// ============================================
// SYSTEM INITIALIZATION
// ============================================
date_default_timezone_set(TIMEZONE);

if (ENABLE_DEBUG_LOG) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 0);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
}

ini_set('memory_limit', '512M');
ini_set('max_execution_time', '300');
