<?php
/**
 * SIEM Dashboard - Simple Version
 * Displays events from jfs_siem database
 */

session_start();

// Check if logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Database connection
$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

// Get statistics
$total_events = $db->query("SELECT COUNT(*) as count FROM security_events")->fetch_assoc()['count'];
$total_agents = $db->query("SELECT COUNT(DISTINCT source_ip) as count FROM security_events")->fetch_assoc()['count'];
$last_event = $db->query("SELECT timestamp FROM security_events ORDER BY timestamp DESC LIMIT 1")->fetch_assoc()['timestamp'] ?? 'N/A';

// Get recent events
$recent_events = $db->query("
    SELECT timestamp, event_type, severity, source_ip, raw_log 
    FROM security_events 
    ORDER BY timestamp DESC 
    LIMIT 20
");

?>
<!DOCTYPE html>
<html>
<head>
    <title>JFS ICT Services - SIEM Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #0f1419; 
            color: #fff;
        }
        
        .header {
            background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
            padding: 30px;
            border-bottom: 1px solid #004499;
        }
        
        .header h1 { font-size: 32px; margin-bottom: 5px; }
        .header p { font-size: 14px; opacity: 0.9; }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 30px; }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-box {
            background: #1a1f26;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #0066cc;
        }
        
        .stat-number { font-size: 32px; font-weight: bold; color: #00d4ff; }
        .stat-label { font-size: 12px; color: #b0b8c1; margin-top: 10px; text-transform: uppercase; }
        
        .events-table {
            background: #1a1f26;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .events-table h2 {
            padding: 20px;
            border-bottom: 1px solid #252d36;
            font-size: 18px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #252d36;
            padding: 12px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            color: #b0b8c1;
        }
        
        td {
            padding: 12px 20px;
            border-bottom: 1px solid #252d36;
            font-size: 13px;
        }
        
        tr:hover { background: #252d36; }
        
        .severity-critical { color: #ff3333; font-weight: bold; }
        .severity-high { color: #ff9900; }
        .severity-medium { color: #ffcc00; }
        .severity-low { color: #00cc66; }
        .severity-info { color: #00d4ff; }
        
        .btn-logout {
            position: absolute;
            top: 20px;
            right: 30px;
            background: #ff3333;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }
        
        .btn-logout:hover { background: #cc0000; }
        
        .btn-remote {
            background: #0066cc;
            color: white;
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn-remote:hover { background: #004499; }
    </style>
</head>
<body>
    <div class="header">
        <h1>JFS ICT Services - SIEM Dashboard</h1>
        <p>Real-time Security Event Monitoring</p>
        <a href="?logout=1" class="btn-logout">Logout</a>
    </div>
    
    <div class="container">
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number"><?php echo number_format($total_events); ?></div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-box">
                <div class="stat-number"><?php echo $total_agents; ?></div>
                <div class="stat-label">Connected Agents</div>
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
                               class="btn-remote">
                                🖥️ Remote Access
                            </a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>
    
    <?php
    // Handle logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit;
    }
    
    $db->close();
    ?>
</body>
</html>
