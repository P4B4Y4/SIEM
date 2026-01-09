<?php
/**
 * Log Analyzer API Endpoint
 * 
 * Analyzes logs using rule-based classification and scoring
 * Returns structured JSON with category, severity, anomaly detection, and recommendations
 */

header('Content-Type: application/json');

require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/log_analyzer.php';

// Get database connection
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

// Initialize analyzer
$analyzer = new LogAnalyzer($db);

// Handle different request types
$action = isset($_GET['action']) ? $_GET['action'] : 'analyze';

switch ($action) {
    case 'analyze':
        handle_analyze();
        break;
    
    case 'analyze_batch':
        handle_analyze_batch();
        break;
    
    case 'get_rules':
        handle_get_rules();
        break;
    
    case 'analyze_event':
        handle_analyze_event();
        break;
    
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action']);
        break;
}

/**
 * Analyze a single log
 */
function handle_analyze() {
    global $analyzer;
    
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
    
    // Analyze the log
    $analysis = $analyzer->analyze($input);
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'analysis' => $analysis,
        'log' => $input
    ]);
}

/**
 * Analyze multiple logs in batch
 */
function handle_analyze_batch() {
    global $analyzer;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'POST method required']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!is_array($input)) {
        http_response_code(400);
        echo json_encode(['error' => 'Expected array of logs']);
        return;
    }
    
    $results = [];
    foreach ($input as $log) {
        $analysis = $analyzer->analyze($log);
        $results[] = [
            'log' => $log,
            'analysis' => $analysis
        ];
    }
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'count' => count($results),
        'results' => $results
    ]);
}

/**
 * Get all rules
 */
function handle_get_rules() {
    global $analyzer;
    
    $category_rules = $analyzer->get_category_rules();
    $severity_keywords = $analyzer->get_severity_keywords();
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'category_rules' => $category_rules,
        'severity_keywords' => $severity_keywords,
        'severity_scale' => [
            '1-3' => 'Normal system operations, no risk indicators',
            '4-6' => 'Failed logins, unusual IP, repeated commands',
            '7-8' => 'Suspicious processes, base64 commands, unexpected connections',
            '9-10' => 'Privilege escalation, persistence indicators, malware keywords'
        ],
        'anomaly_rules' => [
            'repeated_event' => 'Event repeats more than 5 times',
            'unseen_process' => 'Unseen process name',
            'rare_port' => 'Rare port (> 50000)',
            'new_ip' => 'Login from new IP',
            'system_directory_access' => 'File activity in system directories'
        ]
    ]);
}

/**
 * Analyze a stored event from database
 */
function handle_analyze_event() {
    global $analyzer, $db;
    
    $event_id = isset($_GET['event_id']) ? (int)$_GET['event_id'] : null;
    
    if (!$event_id) {
        http_response_code(400);
        echo json_encode(['error' => 'event_id parameter required']);
        return;
    }
    
    // Get event from database
    $result = $db->query("SELECT * FROM security_events WHERE id = $event_id");
    
    if ($result->num_rows === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Event not found']);
        return;
    }
    
    $event = $result->fetch_assoc();
    
    // Parse event data if JSON
    if (isset($event['event_data']) && is_string($event['event_data'])) {
        $event_data = json_decode($event['event_data'], true);
        $event = array_merge($event, $event_data);
    }
    
    // Analyze the event
    $analysis = $analyzer->analyze($event);
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'event_id' => $event_id,
        'event' => $event,
        'analysis' => $analysis
    ]);
}

?>
