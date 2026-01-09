<?php
/**
 * SIEM Dashboard - Working Version
 * Displays events from jfs_siem database
 */

session_start();

// Check if logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php?redirect=dashboard');
    exit;
}

// Database connection
$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

// Get statistics
$total_events = $db->query("SELECT COUNT(*) as count FROM security_events")->fetch_assoc()['count'];
$events_today = $db->query("SELECT COUNT(*) as count FROM security_events WHERE DATE(timestamp) = CURDATE()")->fetch_assoc()['count'];
$critical_events = $db->query("SELECT COUNT(*) as count FROM security_events WHERE severity = 'high'")->fetch_assoc()['count'];
$last_event = $db->query("SELECT timestamp FROM security_events ORDER BY timestamp DESC LIMIT 1")->fetch_assoc()['timestamp'];

// Get recent events
$recent_events = $db->query("
    SELECT event_id, timestamp, event_type, severity, source_ip, raw_log 
    FROM security_events 
    ORDER BY timestamp DESC 
    LIMIT 20
");

?>
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #333; color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }
        .stat-box { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-number { font-size: 32px; font-weight: bold; color: #333; }
        .stat-label { color: #666; font-size: 14px; margin-top: 5px; }
        .events-table { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f0f0f0; padding: 10px; text-align: left; border-bottom: 2px solid #ddd; }
        td { padding: 10px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f9f9f9; }
        .severity-high { color: #d32f2f; font-weight: bold; }
        .severity-medium { color: #f57c00; font-weight: bold; }
        .severity-low { color: #388e3c; font-weight: bold; }
        .severity-info { color: #1976d2; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="navbar-menu">
            <a href="dashboard.php" class="active"><i class="fas fa-home"></i> Dashboard</a>
            <a href="events.php"><i class="fas fa-list"></i> Events</a>
            <a href="threats.php"><i class="fas fa-exclamation-triangle"></i> Threats & Alerts</a>
            <a href="remote-terminal.php"><i class="fas fa-terminal"></i> Remote Terminal</a>
            <a href="task-manager.php"><i class="fas fa-tasks"></i> Task Manager</a>
            <a href="settings.php"><i class="fas fa-cog"></i> Settings</a>
        </div>
        <div class="header">
            <h1>SIEM Dashboard</h1>
            <p>Real-time Security Event Monitoring</p>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-number"><?php echo number_format($total_events); ?></div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-box">
                <div class="stat-number"><?php echo $events_today; ?></div>
                <div class="stat-label">Events Today</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #d32f2f;"><?php echo $critical_events; ?></div>
                <div class="stat-label">Critical Events</div>
            </div>
            <div class="stat-box">
                <div class="stat-number"><?php echo $last_event ? date('H:i', strtotime($last_event)) : 'N/A'; ?></div>
                <div class="stat-label">Last Event</div>
            </div>
        </div>

        <div class="events-table">
            <h2>Recent Events (Last 20)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Description</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($event = $recent_events->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo date('Y-m-d H:i:s', strtotime($event['timestamp'])); ?></td>
                        <td><?php echo htmlspecialchars($event['event_type']); ?></td>
                        <td class="severity-<?php echo $event['severity']; ?>">
                            <?php echo strtoupper($event['severity']); ?>
                        </td>
                        <td><?php echo htmlspecialchars($event['source_ip']); ?></td>
                        <td><?php echo htmlspecialchars(substr($event['raw_log'], 0, 100)); ?></td>
                        <td>
                            <a href="remote-terminal.php?agent=<?php echo urlencode($event['source_ip']); ?>" 
                               style="color: #0066cc; text-decoration: none; font-weight: bold;">
                                💻 Remote Terminal
                            </a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
