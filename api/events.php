<?php
/**
 * Events API Endpoint
 * Provides JSON API for event data retrieval and filtering
 */

session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Set JSON header
header('Content-Type: application/json');

// Check authentication
if (!isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$db = getDatabase();
$action = $_GET['action'] ?? 'list';
$limit = (int)($_GET['limit'] ?? 20);
$offset = (int)($_GET['offset'] ?? 0);
$severity = $_GET['severity'] ?? '';
$event_type = $_GET['event_type'] ?? '';

try {
    switch ($action) {
        case 'list':
            // Get events list
            $where = "WHERE 1=1";
            if ($severity) {
                $where .= " AND severity = '" . $db->escape($severity) . "'";
            }
            if ($event_type) {
                $where .= " AND event_type LIKE '%" . $db->escape($event_type) . "%'";
            }

            $result = $db->query("
                SELECT * FROM security_events 
                $where
                ORDER BY timestamp DESC 
                LIMIT $limit OFFSET $offset
            ");
            
            $events = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
            
            // Get total count
            $countResult = $db->query("SELECT COUNT(*) as total FROM security_events $where");
            $total = $countResult ? $countResult->fetch_assoc()['total'] : 0;

            echo json_encode([
                'success' => true,
                'data' => $events,
                'total' => $total,
                'limit' => $limit,
                'offset' => $offset
            ]);
            break;

        case 'detail':
            // Get single event details
            $event_id = (int)($_GET['id'] ?? 0);
            
            if (!$event_id) {
                throw new Exception('Event ID required');
            }

            $result = $db->query("SELECT * FROM security_events WHERE event_id = $event_id");
            $event = $result ? $result->fetch_assoc() : null;

            if (!$event) {
                throw new Exception('Event not found');
            }

            echo json_encode([
                'success' => true,
                'data' => $event
            ]);
            break;

        case 'stats':
            // Get event statistics
            $result = $db->query("
                SELECT 
                    severity,
                    COUNT(*) as count
                FROM security_events
                GROUP BY severity
            ");
            
            $stats = [];
            if ($result) {
                while ($row = $result->fetch_assoc()) {
                    $stats[$row['severity']] = $row['count'];
                }
            }

            echo json_encode([
                'success' => true,
                'data' => $stats
            ]);
            break;

        case 'recent':
            // Get recent events
            $limit = (int)($_GET['limit'] ?? 10);
            
            $result = $db->query("
                SELECT * FROM security_events 
                ORDER BY timestamp DESC 
                LIMIT $limit
            ");
            
            $events = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];

            echo json_encode([
                'success' => true,
                'data' => $events
            ]);
            break;

        default:
            throw new Exception('Unknown action');
    }

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
