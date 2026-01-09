<?php
/**
 * Clear all agents from database
 * Visit: http://localhost/SIEM/api/clear-agents.php
 */

header('Content-Type: application/json');

$db_file = __DIR__ . '/../data/siem.db';

try {
    if (file_exists($db_file)) {
        $db = new PDO('sqlite:' . $db_file);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Delete all agents
        $db->exec("DELETE FROM agents");
        
        echo json_encode([
            'success' => true,
            'message' => 'All agents cleared from database'
        ]);
    } else {
        echo json_encode([
            'success' => true,
            'message' => 'Database file does not exist'
        ]);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>
