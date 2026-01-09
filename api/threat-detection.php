<?php
/**
 * Threat Detection API Endpoint
 * 
 * Processes normalized logs through the detection engine
 * Returns structured security alerts
 */

session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/threat_detection.php';
require_once '../includes/alert_notifier.php';
require_once '../includes/settings.php';

// Get database connection
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

// Initialize threat detection engine
$engine = new ThreatDetectionEngine($db);

// Handle different request types
$action = isset($_GET['action']) ? $_GET['action'] : 'evaluate';

switch ($action) {
    case 'evaluate':
        handle_evaluate_log();
        break;
    
    case 'get_alerts':
        handle_get_alerts();
        break;
    
    case 'get_alert':
        handle_get_alert();
        break;
    
    case 'update_alert':
        handle_update_alert();
        break;
    
    case 'get_stats':
        handle_get_stats();
        break;
    
    case 'get_rules':
        handle_get_rules();
        break;
    
    case 'get_rule':
        handle_get_rule();
        break;
    
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action']);
        break;
}

/**
 * Evaluate a single log against detection rules
 */
function handle_evaluate_log() {
    global $engine, $db;
    
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
    
    // Evaluate the log
    $alert = $engine->evaluate_log($input);
    
    if ($alert) {
        // Store alert in database
        $engine->store_alert($alert);

        // Send email notification (best-effort)
        try {
            $smtp_settings = (array)getSetting('smtp', []);
            $email_notifications_enabled = (bool)getSetting('email_notifications.enabled', false);
            $default_recipients = (string)getSetting('email_notifications.default_recipients', '');

            if ($email_notifications_enabled && $default_recipients !== '') {
                $smtp_config = [
                    'host' => $smtp_settings['host'] ?? (getenv('SMTP_HOST') ?: 'localhost'),
                    'port' => (int)($smtp_settings['port'] ?? (getenv('SMTP_PORT') ?: 587)),
                    'user' => $smtp_settings['username'] ?? (getenv('SMTP_USER') ?: ''),
                    'pass' => $smtp_settings['password'] ?? (getenv('SMTP_PASS') ?: ''),
                    'from_email' => $smtp_settings['from_email'] ?? (getenv('SMTP_FROM') ?: 'siem@localhost'),
                    'from_name' => $smtp_settings['from_name'] ?? 'SIEM Alert System',
                    'use_smtp' => (bool)($smtp_settings['enabled'] ?? (bool)(getenv('USE_SMTP') ?: false))
                ];

                $notifier = new AlertNotifier($smtp_config);
                $sent = $notifier->send_alert_email($alert, $default_recipients);
                if (!$sent) {
                    error_log('Alert email send failed for alert_id=' . ($alert['alert_id'] ?? 'unknown'));
                }
            }
        } catch (Exception $e) {
            error_log('Alert email exception: ' . $e->getMessage());
        }
        
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'alert' => $alert
        ]);
    } else {
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'alert' => null,
            'message' => 'No matching rules'
        ]);
    }
}

/**
 * Get all alerts with optional filtering
 */
function handle_get_alerts() {
    global $db;
    
    $severity = isset($_GET['severity']) ? $_GET['severity'] : null;
    $status = isset($_GET['status']) ? $_GET['status'] : null;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 100;
    $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
    
    $query = "SELECT * FROM security_alerts WHERE 1=1";
    $params = [];
    $types = '';
    
    if ($severity) {
        $query .= " AND severity = ?";
        $params[] = $severity;
        $types .= 's';
    }
    
    if ($status) {
        $query .= " AND status = ?";
        $params[] = $status;
        $types .= 's';
    }
    
    $query .= " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;
    $types .= 'ii';
    
    $stmt = $db->prepare($query);
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error']);
        return;
    }
    
    if ($types) {
        $stmt->bind_param($types, ...$params);
    }
    
    $stmt->execute();
    $result = $stmt->get_result();
    
    $alerts = [];
    while ($row = $result->fetch_assoc()) {
        $row['details'] = json_decode($row['details'], true);
        $row['recommended_actions'] = json_decode($row['recommended_actions'], true);
        $row['raw_log'] = json_decode($row['raw_log'], true);
        $alerts[] = $row;
    }
    
    // Get total count
    $count_query = "SELECT COUNT(*) as total FROM security_alerts WHERE 1=1";
    if ($severity) {
        $count_query .= " AND severity = '$severity'";
    }
    if ($status) {
        $count_query .= " AND status = '$status'";
    }
    
    $count_result = $db->query($count_query);
    $count_row = $count_result->fetch_assoc();
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'alerts' => $alerts,
        'total' => $count_row['total'],
        'limit' => $limit,
        'offset' => $offset
    ]);
}

/**
 * Get a specific alert
 */
function handle_get_alert() {
    global $db;
    
    $alert_id = isset($_GET['alert_id']) ? $_GET['alert_id'] : null;
    
    if (!$alert_id) {
        http_response_code(400);
        echo json_encode(['error' => 'alert_id parameter required']);
        return;
    }
    
    $stmt = $db->prepare("SELECT * FROM security_alerts WHERE alert_id = ?");
    $stmt->bind_param('s', $alert_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Alert not found']);
        return;
    }
    
    $alert = $result->fetch_assoc();
    $alert['details'] = json_decode($alert['details'], true);
    $alert['recommended_actions'] = json_decode($alert['recommended_actions'], true);
    $alert['raw_log'] = json_decode($alert['raw_log'], true);
    
    // Get alert history
    $history_result = $db->query("SELECT * FROM alert_history WHERE alert_id = '$alert_id' ORDER BY timestamp DESC");
    $alert['history'] = [];
    while ($row = $history_result->fetch_assoc()) {
        $alert['history'][] = $row;
    }
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'alert' => $alert
    ]);
}

/**
 * Update alert status and notes
 */
function handle_update_alert() {
    global $db;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    $alert_id = isset($input['alert_id']) ? $input['alert_id'] : null;
    $status = isset($input['status']) ? $input['status'] : null;
    $notes = isset($input['notes']) ? $input['notes'] : null;
    $assigned_to = isset($input['assigned_to']) ? $input['assigned_to'] : null;
    
    if (!$alert_id) {
        http_response_code(400);
        echo json_encode(['error' => 'alert_id required']);
        return;
    }
    
    // Update alert
    $update_query = "UPDATE security_alerts SET ";
    $updates = [];
    $params = [];
    $types = '';
    
    if ($status) {
        $updates[] = "status = ?";
        $params[] = $status;
        $types .= 's';
    }
    
    if ($notes !== null) {
        $updates[] = "notes = ?";
        $params[] = $notes;
        $types .= 's';
    }
    
    if ($assigned_to) {
        $updates[] = "assigned_to = ?";
        $params[] = $assigned_to;
        $types .= 's';
    }
    
    if (empty($updates)) {
        http_response_code(400);
        echo json_encode(['error' => 'No fields to update']);
        return;
    }
    
    $update_query .= implode(', ', $updates) . " WHERE alert_id = ?";
    $params[] = $alert_id;
    $types .= 's';
    
    $stmt = $db->prepare($update_query);
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error']);
        return;
    }
    
    $stmt->bind_param($types, ...$params);
    
    if (!$stmt->execute()) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update alert']);
        return;
    }
    
    // Log the action
    $action = $status ? "Status changed to $status" : "Updated";
    $user = isset($_SESSION['username']) ? $_SESSION['username'] : 'system';
    
    $history_stmt = $db->prepare("INSERT INTO alert_history (alert_id, action, user, notes) VALUES (?, ?, ?, ?)");
    $history_stmt->bind_param('ssss', $alert_id, $action, $user, $notes);
    $history_stmt->execute();
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'Alert updated successfully'
    ]);
}

/**
 * Get alert statistics
 */
function handle_get_stats() {
    global $engine;
    
    $stats = $engine->get_alert_stats();
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'stats' => $stats
    ]);
}

/**
 * Get all detection rules
 */
function handle_get_rules() {
    global $engine;
    
    $severity = isset($_GET['severity']) ? $_GET['severity'] : null;
    $category = isset($_GET['category']) ? $_GET['category'] : null;
    
    if ($severity) {
        $rules = $engine->get_rules_by_severity($severity);
    } elseif ($category) {
        $rules = $engine->get_rules_by_category($category);
    } else {
        $rules = $engine->get_rules();
    }
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'rules' => $rules,
        'count' => count($rules)
    ]);
}

/**
 * Get a specific rule
 */
function handle_get_rule() {
    global $engine;
    
    $rule_id = isset($_GET['rule_id']) ? $_GET['rule_id'] : null;
    
    if (!$rule_id) {
        http_response_code(400);
        echo json_encode(['error' => 'rule_id parameter required']);
        return;
    }
    
    $rule = $engine->get_rule($rule_id);
    
    if (!$rule) {
        http_response_code(404);
        echo json_encode(['error' => 'Rule not found']);
        return;
    }
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'rule' => $rule
    ]);
}

?>
