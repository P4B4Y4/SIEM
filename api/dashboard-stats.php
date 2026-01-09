<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/../config/config.php';

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Database connection failed']);
    exit;
}

// Last 24 hours trend by hour
$events_by_hour = [];
$alerts_by_hour = [];

// Build 24 buckets (oldest -> newest)
$now = new DateTime('now');
$start = (clone $now)->modify('-23 hours');
$labels = [];
for ($i = 0; $i < 24; $i++) {
    $t = (clone $start)->modify('+' . $i . ' hours');
    $labels[] = $t->format('H:00');
    $events_by_hour[$t->format('Y-m-d H:00:00')] = 0;
    $alerts_by_hour[$t->format('Y-m-d H:00:00')] = 0;
}

// Events: security_events.timestamp
$stmt = $db->prepare("SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as bucket, COUNT(*) as c
                      FROM security_events
                      WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                      GROUP BY bucket");
if ($stmt) {
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $b = $row['bucket'];
        if (isset($events_by_hour[$b])) {
            $events_by_hour[$b] = (int)$row['c'];
        }
    }
    $stmt->close();
}

// Alerts: security_alerts.timestamp (if table exists)
$tables = $db->query("SHOW TABLES LIKE 'security_alerts'");
if ($tables && $tables->num_rows > 0) {
    $stmt2 = $db->prepare("SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as bucket, COUNT(*) as c
                           FROM security_alerts
                           WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                           GROUP BY bucket");
    if ($stmt2) {
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        while ($row = $res2->fetch_assoc()) {
            $b = $row['bucket'];
            if (isset($alerts_by_hour[$b])) {
                $alerts_by_hour[$b] = (int)$row['c'];
            }
        }
        $stmt2->close();
    }
}

$events_series = array_values($events_by_hour);
$alerts_series = array_values($alerts_by_hour);

echo json_encode([
    'success' => true,
    'labels' => $labels,
    'events' => $events_series,
    'alerts' => $alerts_series
]);

$db->close();
