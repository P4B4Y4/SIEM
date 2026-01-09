<?php
/**
 * Alerting System API Endpoint
 * 
 * Standalone endpoint for converting detection outputs to alerts
 * Can be called independently without SIEM backend
 * 
 * Usage:
 *   POST /api/alerting-system.php?action=process_detection
 *   POST /api/alerting-system.php?action=process_batch
 *   GET  /api/alerting-system.php?action=get_mappings
 */

header('Content-Type: application/json');

require_once '../includes/alerting_system.php';

// Initialize alerting system
$alerting_system = new AlertingSystem();

// Get action parameter
$action = isset($_GET['action']) ? $_GET['action'] : 'process_detection';

switch ($action) {
    case 'process_detection':
        handle_process_detection();
        break;
    
    case 'process_batch':
        handle_process_batch();
        break;
    
    case 'get_mappings':
        handle_get_mappings();
        break;
    
    default:
        http_response_code(400);
        echo json_encode([
            'error' => 'Unknown action',
            'available_actions' => [
                'process_detection' => 'Process a single detection',
                'process_batch' => 'Process multiple detections',
                'get_mappings' => 'Get severity and escalation mappings'
            ]
        ]);
        break;
}

/**
 * Process a single detection
 */
function handle_process_detection() {
    global $alerting_system;
    
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
    
    $alert = $alerting_system->process_detection($input);
    
    if (!$alert) {
        http_response_code(400);
        echo json_encode([
            'error' => 'Failed to process detection',
            'required_fields' => ['event_id', 'timestamp', 'computer', 'source', 'category', 'severity']
        ]);
        return;
    }
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'alert' => $alert
    ]);
}

/**
 * Process a batch of detections
 */
function handle_process_batch() {
    global $alerting_system;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!is_array($input)) {
        http_response_code(400);
        echo json_encode(['error' => 'Input must be an array of detections']);
        return;
    }
    
    $result = $alerting_system->process_batch($input);
    
    http_response_code(200);
    echo json_encode($result);
}

/**
 * Get severity and escalation mappings
 */
function handle_get_mappings() {
    global $alerting_system;
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'severity_mapping' => $alerting_system->get_severity_mapping(),
        'escalation_rules' => [
            'severity_8_plus' => 'Escalate to SOC Level 2 immediately',
            'severity_5_to_7' => 'Investigate within 1 hour',
            'severity_below_5' => 'Review in normal shift'
        ],
        'alert_format' => [
            'alert_id' => 'Unique identifier (ALERT_XXXXXXXX)',
            'title' => 'Category - Brief Description',
            'alert_level' => 'Informational, Warning, or Critical',
            'timestamp' => 'ISO 8601 timestamp',
            'computer' => 'Source computer name',
            'source' => 'Event source',
            'category' => 'Detection category',
            'severity' => 'Severity level (low, medium, high, critical)',
            'anomaly' => 'Yes/No anomaly indicator',
            'reason' => 'Detection reason',
            'recommendation' => 'Recommended action',
            'escalation' => 'Escalation instruction',
            'raw_log' => 'Original log data (unchanged)'
        ]
    ]);
}

?>
