<?php
/**
 * Alert Email Notification API
 * 
 * Sends email notifications for alerts
 * 
 * Usage:
 *   POST /api/send-alert-email.php?action=send_alert
 *   POST /api/send-alert-email.php?action=send_batch
 *   POST /api/send-alert-email.php?action=send_latest
 *   POST /api/send-alert-email.php?action=test_smtp
 */

header('Content-Type: application/json');

// Avoid empty responses on fatal errors
ini_set('display_errors', '0');
error_reporting(E_ALL);
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) {
            header('Content-Type: application/json');
            http_response_code(500);
        }
        echo json_encode([
            'success' => false,
            'error' => 'Server error: ' . $err['message'],
            'file' => basename($err['file']),
            'line' => $err['line']
        ]);
    }
});

require_once '../includes/alert_notifier.php';
require_once '../config/config.php';
require_once '../includes/settings.php';

// DB connection (used for sending latest alerts)
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    $db = null;
}

/**
 * Send/resend NEW alerts that are due for notification.
 * Policy: status='new' and (last_emailed_at IS NULL OR last_emailed_at < NOW() - 30 minutes)
 * Optional query params:
 *  - limit (default 50, max 200)
 */
function handle_send_pending() {
    global $notifier;
    global $db;
    global $email_notifications_enabled;
    global $default_recipients;

    $cron_token_required = (string)getSetting('email_notifications.cron_token', '');
    if ($cron_token_required !== '') {
        $provided = '';
        if (isset($_GET['token'])) {
            $provided = (string)$_GET['token'];
        } elseif (isset($_SERVER['HTTP_X_SIEM_CRON_TOKEN'])) {
            $provided = (string)$_SERVER['HTTP_X_SIEM_CRON_TOKEN'];
        }
        if (!hash_equals($cron_token_required, $provided)) {
            http_response_code(401);
            echo json_encode(['success' => false, 'error' => 'Unauthorized']);
            return;
        }
    }

    $debug_log = __DIR__ . '/../logs/email_debug.log';
    $debug_prefix = '[' . date('Y-m-d H:i:s') . '] send_pending: ';
    @error_log($debug_prefix . 'start' . "\n", 3, $debug_log);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        @error_log($debug_prefix . 'blocked: method=' . ($_SERVER['REQUEST_METHOD'] ?? '') . "\n", 3, $debug_log);
        return;
    }

    if (!$email_notifications_enabled) {
        http_response_code(200);
        echo json_encode([
            'success' => false,
            'message' => 'Email notifications are disabled'
        ]);
        @error_log($debug_prefix . 'blocked: notifications disabled' . "\n", 3, $debug_log);
        return;
    }

    if ($default_recipients === '') {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'No default recipient configured'
        ]);
        @error_log($debug_prefix . 'blocked: no default recipients' . "\n", 3, $debug_log);
        return;
    }

    if (!$db) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Database connection failed'
        ]);
        @error_log($debug_prefix . 'blocked: db connection failed' . "\n", 3, $debug_log);
        return;
    }

    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    if ($limit < 1) $limit = 50;
    if ($limit > 200) $limit = 200;

    $cutoff = date('Y-m-d H:i:s', time() - (30 * 60));
    @error_log($debug_prefix . 'cutoff=' . $cutoff . ' limit=' . $limit . "\n", 3, $debug_log);

    $stmt = $db->prepare(
        "SELECT * FROM security_alerts WHERE status = 'new' AND (last_emailed_at IS NULL OR last_emailed_at < ?) ORDER BY timestamp DESC LIMIT ?"
    );
    if (!$stmt) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Query prepare failed'
        ]);
        @error_log($debug_prefix . 'error: prepare failed: ' . ($db->error ?? '') . "\n", 3, $debug_log);
        return;
    }

    $stmt->bind_param('si', $cutoff, $limit);
    $stmt->execute();
    $res = $stmt->get_result();

    $alerts = [];
    while ($res && ($row = $res->fetch_assoc())) {
        $row['details'] = json_decode($row['details'], true);
        $row['recommended_actions'] = json_decode($row['recommended_actions'], true);
        $row['raw_log'] = json_decode($row['raw_log'], true);
        $alerts[] = $row;
    }
    $stmt->close();

    @error_log($debug_prefix . 'selected=' . count($alerts) . "\n", 3, $debug_log);

    $sent = 0;
    $failed = 0;
    $results = [];

    $upd = $db->prepare(
        "UPDATE security_alerts SET last_emailed_at = NOW(), email_count = email_count + 1, email_last_error = NULL WHERE alert_id = ?"
    );
    $updFail = $db->prepare(
        "UPDATE security_alerts SET email_last_error = ? WHERE alert_id = ?"
    );

    foreach ($alerts as $a) {
        $alertId = (string)($a['alert_id'] ?? '');
        if ($alertId === '') {
            continue;
        }

        $ok = $notifier->send_alert_email($a, $default_recipients);
        if ($ok) {
            $sent++;
            if ($upd) {
                $upd->bind_param('s', $alertId);
                $upd->execute();
            }
            $results[$alertId] = true;
        } else {
            $failed++;
            $err = $notifier->get_last_error() ?: 'Failed to send email';
            if ($updFail) {
                $updFail->bind_param('ss', $err, $alertId);
                $updFail->execute();
            }
            $results[$alertId] = $err;
        }
    }

    if ($upd) $upd->close();
    if ($updFail) $updFail->close();

    http_response_code(200);
    echo json_encode([
        'success' => true,
        'recipient' => $default_recipients,
        'cutoff' => $cutoff,
        'total' => count($alerts),
        'sent' => $sent,
        'failed' => $failed,
        'results' => $results
    ]);
}

// Get SMTP configuration from settings.json (preferred) with env fallback
$smtp_settings = (array)getSetting('smtp', []);
$email_notifications_enabled = (bool)getSetting('email_notifications.enabled', false);
$default_recipients = (string)getSetting('email_notifications.default_recipients', '');

$smtp_config = [
    'host' => $smtp_settings['host'] ?? (getenv('SMTP_HOST') ?: 'localhost'),
    'port' => (int)($smtp_settings['port'] ?? (getenv('SMTP_PORT') ?: 587)),
    'user' => $smtp_settings['username'] ?? (getenv('SMTP_USER') ?: ''),
    'pass' => $smtp_settings['password'] ?? (getenv('SMTP_PASS') ?: ''),
    'from_email' => $smtp_settings['from_email'] ?? (getenv('SMTP_FROM') ?: 'siem@localhost'),
    'from_name' => $smtp_settings['from_name'] ?? 'SIEM Alert System',
    'use_smtp' => (bool)($smtp_settings['enabled'] ?? (bool)(getenv('USE_SMTP') ?: false)),
    'encryption' => $smtp_settings['encryption'] ?? null
];

// Initialize notifier
$notifier = new AlertNotifier($smtp_config);

// Get action parameter
$action = isset($_GET['action']) ? $_GET['action'] : 'send_alert';

switch ($action) {
    case 'send_alert':
        handle_send_alert();
        break;
    
    case 'send_latest':
        handle_send_latest();
        break;

    case 'send_pending':
        handle_send_pending();
        break;
    
    case 'send_batch':
        handle_send_batch();
        break;
    
    case 'test_smtp':
        handle_test_smtp();
        break;
    
    default:
        http_response_code(400);
        echo json_encode([
            'error' => 'Unknown action',
            'available_actions' => [
                'send_alert' => 'Send email for single alert',
                'send_batch' => 'Send emails for multiple alerts',
                'send_latest' => 'Send latest alerts from DB',
                'send_pending' => 'Send/resend NEW alerts that are due (every 30 minutes)',
                'test_smtp' => 'Test SMTP connection'
            ]
        ]);
        break;
}

/**
 * Send alert email
 */
function handle_send_alert() {
    global $notifier;
    global $email_notifications_enabled;
    global $default_recipients;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        return;
    }

    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    // Validate required fields
    if (!isset($input['alert'])) {
        http_response_code(400);
        echo json_encode([
            'error' => 'Missing required fields',
            'required' => ['alert'],
            'optional' => ['recipient']
        ]);
        return;
    }
    
    $alert = $input['alert'];
    $recipient = $input['recipient'] ?? null;

    if (!$email_notifications_enabled) {
        http_response_code(200);
        echo json_encode([
            'success' => false,
            'alert_id' => $alert['alert_id'] ?? 'unknown',
            'message' => 'Email notifications are disabled'
        ]);
        return;
    }

    if ($recipient === null || $recipient === '') {
        $recipient = $default_recipients;
    }

    if ($recipient === null || $recipient === '') {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'alert_id' => $alert['alert_id'] ?? 'unknown',
            'message' => 'No recipient provided and no default recipient configured'
        ]);
        return;
    }
    
    // Send email
    $result = $notifier->send_alert_email($alert, $recipient);
    
    http_response_code(200);
    echo json_encode([
        'success' => $result,
        'alert_id' => $alert['alert_id'] ?? 'unknown',
        'recipient' => $recipient,
        'message' => $result ? 'Email sent successfully' : 'Failed to send email',
        'error' => $result ? null : $notifier->get_last_error()
    ]);
}

/**
 * Send latest alerts from DB
 * Optional query params:
 *  - limit (default 20, max 100)
 *  - severity (critical/high/medium/low)
 *  - status (new/acknowledged/resolved)
 */
function handle_send_latest() {
    global $notifier;
    global $db;
    global $email_notifications_enabled;
    global $default_recipients;
 
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        return;
    }
 
    if (!$email_notifications_enabled) {
        http_response_code(200);
        echo json_encode([
            'success' => false,
            'message' => 'Email notifications are disabled'
        ]);
        return;
    }
 
    if ($default_recipients === '') {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'No default recipient configured'
        ]);
        return;
    }
 
    if (!$db) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Database connection failed'
        ]);
        return;
    }
 
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 20;
    if ($limit < 1) $limit = 20;
    if ($limit > 100) $limit = 100;
 
    $severity = isset($_GET['severity']) ? trim((string)$_GET['severity']) : '';
    $status = isset($_GET['status']) ? trim((string)$_GET['status']) : '';
 
    $query = "SELECT * FROM security_alerts WHERE 1=1";
    $types = '';
    $params = [];
 
    if ($severity !== '') {
        $query .= " AND severity = ?";
        $types .= 's';
        $params[] = $severity;
    }
    if ($status !== '') {
        $query .= " AND status = ?";
        $types .= 's';
        $params[] = $status;
    }
 
    $query .= " ORDER BY timestamp DESC LIMIT ?";
    $types .= 'i';
    $params[] = $limit;
 
    $stmt = $db->prepare($query);
    if (!$stmt) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Query prepare failed'
        ]);
        return;
    }
 
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $res = $stmt->get_result();
 
    $alerts = [];
    while ($res && ($row = $res->fetch_assoc())) {
        $row['details'] = json_decode($row['details'], true);
        $row['recommended_actions'] = json_decode($row['recommended_actions'], true);
        $row['raw_log'] = json_decode($row['raw_log'], true);
        $alerts[] = $row;
    }
    $stmt->close();
 
    $sent = 0;
    $failed = 0;
    $results = [];
 
    foreach ($alerts as $a) {
        $ok = $notifier->send_alert_email($a, $default_recipients);
        $results[$a['alert_id'] ?? ('row_' . $sent)] = $ok ? true : ($notifier->get_last_error() ?: false);
        if ($ok) {
            $sent++;
        } else {
            $failed++;
        }
    }
 
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'recipient' => $default_recipients,
        'total' => count($alerts),
        'sent' => $sent,
        'failed' => $failed,
        'results' => $results
    ]);
}

/**
 * Send batch alert emails
 */
function handle_send_batch() {
    global $notifier;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    // Validate required fields
    if (!isset($input['alerts']) || !isset($input['recipient'])) {
        http_response_code(400);
        echo json_encode([
            'error' => 'Missing required fields',
            'required' => ['alerts (array)', 'recipient']
        ]);
        return;
    }
    
    $alerts = $input['alerts'];
    $recipient = $input['recipient'];
    
    if (!is_array($alerts)) {
        http_response_code(400);
        echo json_encode(['error' => 'alerts must be an array']);
        return;
    }
    
    // Send emails
    $results = $notifier->send_batch_alerts($alerts, $recipient);
    
    $sent = 0;
    $failed = 0;
    
    foreach ($results as $success) {
        if ($success) {
            $sent++;
        } else {
            $failed++;
        }
    }
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'total' => count($alerts),
        'sent' => $sent,
        'failed' => $failed,
        'results' => $results
    ]);
}

/**
 * Test SMTP connection
 */
function handle_test_smtp() {
    global $notifier;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        return;
    }
    
    $result = $notifier->test_connection();
    
    http_response_code(200);
    echo json_encode($result);
}

?>
