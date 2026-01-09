<?php
/**
 * Test script to register sample agents
 * Visit: http://localhost/SIEM/api/test-register-agents.php
 */

header('Content-Type: application/json');

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
    
    // Clear existing agents
    $db->exec("DELETE FROM agents");
    
    // Insert test agents
    $test_agents = [
        ['agent-001', 'DESKTOP-USER1', '192.168.1.100', 'DESKTOP-USER1'],
        ['agent-002', 'LAPTOP-ADMIN', '192.168.1.101', 'LAPTOP-ADMIN'],
        ['agent-003', 'SERVER-DC01', '192.168.1.50', 'SERVER-DC01'],
        ['agent-004', 'WORKSTATION-DEV', '192.168.1.102', 'WORKSTATION-DEV'],
        ['agent-005', 'FILESERVER-01', '192.168.1.51', 'FILESERVER-01'],
    ];
    
    $stmt = $db->prepare("INSERT INTO agents (id, name, ip, hostname, status, last_seen, created_at) VALUES (?, ?, ?, ?, 'online', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)");
    
    foreach ($test_agents as $agent) {
        $stmt->execute($agent);
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Test agents registered successfully',
        'agents_count' => count($test_agents),
        'agents' => $test_agents
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>
