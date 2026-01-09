<?php
/**
 * JFS SIEM - Agent Registration
 * Agents register themselves when they connect
 */

header('Content-Type: application/json');

// Log all registration attempts
$log_file = __DIR__ . '/../logs/agent_registration.log';
@mkdir(dirname($log_file), 0777, true);
file_put_contents($log_file, "[" . date('Y-m-d H:i:s') . "] Request received from " . $_SERVER['REMOTE_ADDR'] . "\n", FILE_APPEND);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    echo json_encode(['error' => 'POST required']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
file_put_contents($log_file, "[" . date('Y-m-d H:i:s') . "] Input: " . json_encode($input) . "\n", FILE_APPEND);

$agent_id = $input['agent_id'] ?? uniqid('agent-');
$agent_name = $input['agent_name'] ?? 'Unknown';
$agent_ip = $input['agent_ip'] ?? $_SERVER['REMOTE_ADDR'];
$hostname = $input['hostname'] ?? gethostname();

// Get database connection
$db_file = __DIR__ . '/../data/siem.db';
@mkdir(dirname($db_file), 0777, true);

try {
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create agents table if not exists
    $db->exec("CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        ip TEXT NOT NULL,
        hostname TEXT,
        status TEXT DEFAULT 'online',
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Check if agent exists
    $stmt = $db->prepare("SELECT id FROM agents WHERE id = ?");
    $stmt->execute([$agent_id]);
    $exists = $stmt->fetch();
    
    if ($exists) {
        // Update existing agent
        $stmt = $db->prepare("UPDATE agents SET name = ?, ip = ?, hostname = ?, status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$agent_name, $agent_ip, $hostname, $agent_id]);
    } else {
        // Insert new agent
        $stmt = $db->prepare("INSERT INTO agents (id, name, ip, hostname, status, last_seen, created_at) VALUES (?, ?, ?, ?, 'online', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)");
        $stmt->execute([$agent_id, $agent_name, $agent_ip, $hostname]);
    }
    
    echo json_encode([
        'success' => true,
        'agent_id' => $agent_id,
        'message' => 'Agent registered successfully'
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>
