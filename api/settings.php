<?php
/**
 * Settings API Endpoint
 * Handles settings operations and testing
 */

session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/settings.php';

// Set JSON header
header('Content-Type: application/json');

// Ensure errors don't result in an empty response
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

// Check authentication
if (!isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

// Check admin role for sensitive operations
$action = $_GET['action'] ?? '';
$sensitiveActions = ['test_database', 'test_email', 'backup', 'save_ai'];

if (in_array($action, $sensitiveActions) && !isAdmin()) {
    // Fallback: if session role is missing/outdated, verify from DB
    if (isset($_SESSION['user_id'])) {
        $dbTmp = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
        if (!$dbTmp->connect_error) {
            $uid = (int)$_SESSION['user_id'];
            $res = $dbTmp->query("SELECT role FROM users WHERE user_id = $uid LIMIT 1");
            if ($res && ($row = $res->fetch_assoc()) && ($row['role'] ?? '') === 'admin') {
                $_SESSION['role'] = 'admin';
            }
        }
        if (isset($dbTmp) && $dbTmp instanceof mysqli) {
            $dbTmp->close();
        }
    }

    if (in_array($action, $sensitiveActions) && !isAdmin()) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Admin access required']);
    exit;
    }
}

try {
    switch ($action) {
        case 'get':
            // Get setting value
            $key = $_GET['key'] ?? '';
            if (!$key) {
                throw new Exception('Key parameter required');
            }
            
            $value = getSetting($key);
            echo json_encode([
                'success' => true,
                'key' => $key,
                'value' => $value
            ]);
            break;

        case 'set':
            // Set setting value
            $key = $_POST['key'] ?? '';
            $value = $_POST['value'] ?? '';
            
            if (!$key) {
                throw new Exception('Key parameter required');
            }
            
            setSetting($key, $value);
            
            echo json_encode([
                'success' => true,
                'message' => 'Setting updated successfully',
                'key' => $key,
                'value' => $value
            ]);
            break;

        case 'test_database':
            // Test database connection
            $data = json_decode(file_get_contents('php://input'), true);
            
            $host = $data['host'] ?? DB_HOST;
            $user = $data['user'] ?? DB_USER;
            $pass = $data['pass'] ?? DB_PASS;
            $name = $data['name'] ?? DB_NAME;
            
            $result = testDatabaseConnection($host, $user, $pass, $name);
            
            echo json_encode($result);
            break;

        case 'test_email':
            // Test email connection
            $data = json_decode(file_get_contents('php://input'), true);
            
            $host = $data['host'] ?? '';
            $port = $data['port'] ?? 587;
            $user = $data['user'] ?? '';
            $pass = $data['pass'] ?? '';
            
            if (!$host) {
                throw new Exception('SMTP host required');
            }
            
            $result = testEmailConnection($host, $port, $user, $pass);
            
            echo json_encode($result);
            break;

        case 'backup':
            // Create backup
            $result = createBackup();
            
            echo json_encode($result);
            break;

        case 'backup_status':
            // Get backup status
            $status = getBackupStatus();
            
            echo json_encode([
                'success' => true,
                'data' => $status
            ]);
            break;

        case 'get_all':
            // Get all settings
            $settings = getAllSettings();
            
            echo json_encode([
                'success' => true,
                'data' => $settings
            ]);
            break;

        case 'save_ai':
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) {
                throw new Exception('Invalid JSON input');
            }

            $enabled = !empty($data['enabled']);
            $provider = isset($data['provider']) ? (string)$data['provider'] : 'groq';
            $model = isset($data['model']) ? (string)$data['model'] : 'openai/gpt-oss-20b';
            $api_key = isset($data['api_key']) ? (string)$data['api_key'] : '';

            $ok = true;
            $ok = $ok && setSetting('ai.enabled', $enabled);
            $ok = $ok && setSetting('ai.provider', $provider);
            $ok = $ok && setSetting('ai.model', $model);
            if ($api_key !== '') {
                $ok = $ok && setSetting('ai.api_key', $api_key);
            }

            if (!$ok) {
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to write AI settings to config/settings.json (check Windows file permissions / read-only attribute)'
                ]);
                break;
            }

            echo json_encode([
                'success' => true,
                'message' => 'AI settings saved'
            ]);
            break;

        default:
            throw new Exception('Unknown action: ' . $action);
    }

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
