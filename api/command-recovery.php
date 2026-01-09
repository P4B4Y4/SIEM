<?php
header('Content-Type: application/json');
session_start();

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/database.php';

$action = $_GET['action'] ?? '';
$agent = $_GET['agent'] ?? '';
$older_than = intval($_GET['older_than'] ?? 120);
if ($older_than < 0) $older_than = 0;

$db = getDatabase();
if (!$db) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'error' => 'Database connection failed']);
    exit;
}

$conn = $db->getConnection();

try {
    if ($action === 'cleanup_agent') {
        if ($agent === '') throw new Exception('agent required');

        $stmt = $conn->prepare("UPDATE remote_commands\n            SET status='failed', error='force_cleanup', completed_at=NOW()\n            WHERE status='pending'\n              AND (agent_name = ? OR LOWER(agent_name) = LOWER(?))\n              AND timestamp < (NOW() - INTERVAL ? SECOND)");
        if (!$stmt) throw new Exception('DB prepare failed');
        $stmt->bind_param('ssi', $agent, $agent, $older_than);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();

        echo json_encode(['status' => 'ok', 'scope' => 'agent', 'agent' => $agent, 'older_than' => $older_than, 'affected' => $affected]);
        exit;
    }

    if ($action === 'cleanup_all') {
        $stmt = $conn->prepare("UPDATE remote_commands\n            SET status='failed', error='force_cleanup', completed_at=NOW()\n            WHERE status='pending'\n              AND timestamp < (NOW() - INTERVAL ? SECOND)");
        if (!$stmt) throw new Exception('DB prepare failed');
        $stmt->bind_param('i', $older_than);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();

        echo json_encode(['status' => 'ok', 'scope' => 'all', 'older_than' => $older_than, 'affected' => $affected]);
        exit;
    }

    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => 'Invalid action']);
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => $e->getMessage()]);
}
