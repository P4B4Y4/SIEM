<?php
session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Check authentication
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user = ['username' => $_SESSION['username'] ?? 'Admin', 'role' => 'user'];
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);

// Get filter parameters
$severity_filter = isset($_GET['severity']) ? $_GET['severity'] : '';
$status_filter = isset($_GET['status']) ? $_GET['status'] : '';
$category_filter = isset($_GET['category']) ? $_GET['category'] : '';

// Build queries
$alert_query = "SELECT * FROM security_alerts WHERE 1=1";
$event_query = "SELECT * FROM security_events WHERE 1=1";

if ($severity_filter) {
    $severity_filter = $db->real_escape_string($severity_filter);
    $alert_query .= " AND severity = '$severity_filter'";
}

if ($status_filter) {
    $status_filter = $db->real_escape_string($status_filter);
    $alert_query .= " AND status = '$status_filter'";
}

// Get alerts
$alert_query .= " ORDER BY timestamp DESC LIMIT 50";
$alerts_result = $db->query($alert_query);
$alerts = [];
while ($row = $alerts_result->fetch_assoc()) {
    $row['details'] = json_decode($row['details'], true);
    $row['recommended_actions'] = json_decode($row['recommended_actions'], true);
    $alerts[] = $row;
}

// Get recent events
$events_result = $db->query("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 50");
$events = [];
while ($row = $events_result->fetch_assoc()) {
    $row['event_data'] = json_decode($row['event_data'], true);
    $events[] = $row;
}

// Get statistics
$total_alerts = $db->query("SELECT COUNT(*) as count FROM security_alerts")->fetch_assoc()['count'];
$critical_alerts = $db->query("SELECT COUNT(*) as count FROM security_alerts WHERE severity = 'critical'")->fetch_assoc()['count'];
$high_alerts = $db->query("SELECT COUNT(*) as count FROM security_alerts WHERE severity = 'high'")->fetch_assoc()['count'];
$total_events = $db->query("SELECT COUNT(*) as count FROM security_events")->fetch_assoc()['count'];

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Detection Dashboard - <?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        
        .navbar {
            background: white;
            padding: 15px 30px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .navbar-brand {
            font-size: 20px;
            font-weight: 600;
            color: #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .navbar-menu {
            display: flex;
            gap: 30px;
        }
        
        .navbar-menu a {
            text-decoration: none;
            color: #666;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: color 0.3s;
        }
        
        .navbar-menu a:hover,
        .navbar-menu a.active {
            color: #667eea;
        }
        
        .user-menu {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .btn-logout {
            background: #ef4444;
            color: white;
            padding: 8px 16px;
            border-radius: 5px;
            text-decoration: none;
            font-size: 13px;
            transition: background 0.3s;
        }
        
        .btn-logout:hover {
            background: #dc2626;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }
        
        .page-title {
            font-size: 32px;
            margin-bottom: 30px;
            color: #333;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        .stat-label {
            color: #999;
            font-size: 12px;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 600;
            color: #667eea;
        }
        
        .stat-card.critical .stat-value {
            color: #ef4444;
        }
        
        .stat-card.high .stat-value {
            color: #f59e0b;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #eee;
        }
        
        .tab {
            padding: 15px 20px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 14px;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab:hover {
            color: #667eea;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .alerts-table,
        .events-table {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f9f9f9;
            padding: 15px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #666;
            border-bottom: 1px solid #eee;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #eee;
            font-size: 13px;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .severity-high {
            background: #fef3c7;
            color: #92400e;
        }
        
        .severity-medium {
            background: #dbeafe;
            color: #1e40af;
        }
        
        .severity-low {
            background: #dcfce7;
            color: #166534;
        }
        
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
        }
        
        .status-new {
            background: #e0e7ff;
            color: #3730a3;
        }
        
        .status-acknowledged {
            background: #fef3c7;
            color: #92400e;
        }
        
        .status-resolved {
            background: #dcfce7;
            color: #166534;
        }
        
        .category-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            background: #e0e7ff;
            color: #3730a3;
        }
        
        .btn-view {
            background: #667eea;
            color: white;
            padding: 6px 12px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .btn-view:hover {
            background: #5568d3;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 10px;
            max-width: 700px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .modal-header h2 {
            font-size: 20px;
        }
        
        .btn-close {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #999;
        }
        
        .detail-row {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .detail-label {
            font-weight: 600;
            color: #666;
            min-width: 150px;
        }
        
        .detail-value {
            color: #333;
            word-break: break-word;
        }
        
        .recommendations {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        
        .recommendations h4 {
            margin-bottom: 10px;
            color: #333;
        }
        
        .recommendations li {
            margin-bottom: 8px;
            color: #666;
            font-size: 13px;
        }
        
        .recommendations li:before {
            content: "→ ";
            color: #667eea;
            font-weight: bold;
            margin-right: 8px;
        }
        
        .filters {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            align-items: flex-end;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        
        .filter-group label {
            font-size: 13px;
            font-weight: 600;
            color: #666;
        }
        
        .filter-group select {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 13px;
        }
        
        .btn-filter {
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
        }
        
        .btn-filter:hover {
            background: #5568d3;
        }
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar">
        <div class="navbar-brand">
            <i class="fas fa-shield-alt"></i>
            <span><?php echo APP_NAME; ?></span>
        </div>
        <div class="navbar-menu">
            <a href="dashboard.php"><i class="fas fa-home"></i> Dashboard</a>
            <a href="events.php"><i class="fas fa-list"></i> Events</a>
            <a href="threats.php" class="active"><i class="fas fa-exclamation-triangle"></i> Threats & Alerts</a>
            <a href="remote-terminal.php"><i class="fas fa-terminal"></i> Remote Terminal</a>
            <a href="task-manager.php"><i class="fas fa-tasks"></i> Task Manager</a>
            <a href="settings.php"><i class="fas fa-cog"></i> Settings</a>
        </div>
        <div class="user-menu">
            <div style="text-align: right; font-size: 13px;">
                <div style="font-weight: 600; color: #333;"><?php echo htmlspecialchars($user['username']); ?></div>
                <div style="color: #999;"><?php echo htmlspecialchars(ucfirst($user['role'])); ?></div>
            </div>
            <a href="?logout=1" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <h1 class="page-title">
            <i class="fas fa-exclamation-triangle"></i> Threat Detection Dashboard
        </h1>

        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-label">Critical Alerts</div>
                <div class="stat-value"><?php echo $critical_alerts; ?></div>
            </div>
            <div class="stat-card high">
                <div class="stat-label">High Alerts</div>
                <div class="stat-value"><?php echo $high_alerts; ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Alerts</div>
                <div class="stat-value"><?php echo $total_alerts; ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Events</div>
                <div class="stat-value"><?php echo $total_events; ?></div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="switchTab('alerts')">
                <i class="fas fa-bell"></i> Threat Alerts
            </button>
            <button class="tab" onclick="switchTab('events')">
                <i class="fas fa-list"></i> Recent Events
            </button>
        </div>

        <!-- Alerts Tab -->
        <div id="alerts" class="tab-content active">
            <div class="filters">
                <form method="GET" style="display: flex; gap: 15px; align-items: flex-end; width: 100%;">
                    <div class="filter-group">
                        <label>Severity</label>
                        <select name="severity">
                            <option value="">All</option>
                            <option value="critical" <?php echo $severity_filter === 'critical' ? 'selected' : ''; ?>>Critical</option>
                            <option value="high" <?php echo $severity_filter === 'high' ? 'selected' : ''; ?>>High</option>
                            <option value="medium" <?php echo $severity_filter === 'medium' ? 'selected' : ''; ?>>Medium</option>
                            <option value="low" <?php echo $severity_filter === 'low' ? 'selected' : ''; ?>>Low</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Status</label>
                        <select name="status">
                            <option value="">All</option>
                            <option value="new" <?php echo $status_filter === 'new' ? 'selected' : ''; ?>>New</option>
                            <option value="acknowledged" <?php echo $status_filter === 'acknowledged' ? 'selected' : ''; ?>>Acknowledged</option>
                            <option value="resolved" <?php echo $status_filter === 'resolved' ? 'selected' : ''; ?>>Resolved</option>
                        </select>
                    </div>
                    <button type="submit" class="btn-filter">Filter</button>
                </form>
            </div>

            <div class="alerts-table">
                <table>
                    <thead>
                        <tr>
                            <th>Alert ID</th>
                            <th>Title</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Timestamp</th>
                            <th>Computer</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (count($alerts) > 0): ?>
                            <?php foreach ($alerts as $alert): ?>
                                <tr>
                                    <td><code style="font-size: 11px;"><?php echo htmlspecialchars(substr($alert['alert_id'], 0, 12)); ?></code></td>
                                    <td><?php echo htmlspecialchars($alert['title']); ?></td>
                                    <td>
                                        <span class="severity-badge severity-<?php echo $alert['severity']; ?>">
                                            <?php echo strtoupper($alert['severity']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="status-badge status-<?php echo $alert['status']; ?>">
                                            <?php echo ucfirst($alert['status']); ?>
                                        </span>
                                    </td>
                                    <td><?php echo date('M d, H:i', strtotime($alert['timestamp'])); ?></td>
                                    <td><?php echo htmlspecialchars($alert['details']['computer'] ?? 'N/A'); ?></td>
                                    <td>
                                        <button class="btn-view" onclick="viewAlert('<?php echo htmlspecialchars($alert['alert_id']); ?>', this)">
                                        View
                                    </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="7" style="text-align: center; color: #999; padding: 40px;">
                                    No alerts found
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Events Tab -->
        <div id="events" class="tab-content">
            <div class="events-table">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Event Type</th>
                            <th>Severity</th>
                            <th>Computer</th>
                            <th>Process</th>
                            <th>Raw Log</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (count($events) > 0): ?>
                            <?php foreach ($events as $event): ?>
                                <tr>
                                    <td><?php echo date('M d, H:i', strtotime($event['timestamp'])); ?></td>
                                    <td><?php echo htmlspecialchars($event['event_type']); ?></td>
                                    <td>
                                        <span class="severity-badge severity-<?php echo $event['severity']; ?>">
                                            <?php echo strtoupper($event['severity']); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($event['source_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($event['process_name']); ?></td>
                                    <td><?php echo htmlspecialchars(substr($event['raw_log'], 0, 50)); ?>...</td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="6" style="text-align: center; color: #999; padding: 40px;">
                                    No events found
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Alert Details Modal -->
    <div id="alertModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Alert Details</h2>
                <button class="btn-close" onclick="closeModal()">&times;</button>
            </div>
            <div id="alertDetails"></div>
        </div>
    </div>

    <script>
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        function viewAlert(alertId, button) {
            try {
                // Fetch alert data via API
                fetch('/SIEM/api/threat-detection.php?action=get_alert&alert_id=' + encodeURIComponent(alertId))
                    .then(response => response.json())
                    .then(data => {
                        if (!data.success || !data.alert) {
                            throw new Error('Alert not found');
                        }
                        
                        const alert = data.alert;
                        
                        let html = `
                            <div class="detail-row">
                                <div class="detail-label">Alert ID:</div>
                                <div class="detail-value"><code>${escapeHtml(alert.alert_id)}</code></div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Title:</div>
                                <div class="detail-value">${escapeHtml(alert.title)}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Severity:</div>
                                <div class="detail-value">
                                    <span class="severity-badge severity-${alert.severity}">
                                        ${alert.severity.toUpperCase()}
                                    </span>
                                </div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Status:</div>
                                <div class="detail-value">
                                    <span class="status-badge status-${alert.status}">
                                        ${alert.status.charAt(0).toUpperCase() + alert.status.slice(1)}
                                    </span>
                                </div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Timestamp:</div>
                                <div class="detail-value">${escapeHtml(alert.timestamp)}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Computer:</div>
                                <div class="detail-value">${escapeHtml(alert.details ? alert.details.computer : 'N/A')}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Description:</div>
                                <div class="detail-value">${escapeHtml(alert.description)}</div>
                            </div>
                            
                            <div class="recommendations">
                                <h4>Recommended Actions:</h4>
                                <ul>
                                    ${(alert.recommended_actions || []).map(action => `<li>${escapeHtml(action)}</li>`).join('')}
                                </ul>
                            </div>
                        `;
                        
                        document.getElementById('alertDetails').innerHTML = html;
                        document.getElementById('alertModal').classList.add('active');
                    })
                    .catch(e => {
                        console.error('Error loading alert:', e);
                        document.getElementById('alertDetails').innerHTML = '<p style="color: red;">Error loading alert details. Please try again.</p>';
                        document.getElementById('alertModal').classList.add('active');
                    });
            } catch (e) {
                console.error('Error:', e);
                alert('Error loading alert details');
            }
        }
        
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }
        
        function closeModal() {
            document.getElementById('alertModal').classList.remove('active');
        }
        
        // Close modal when clicking outside
        document.addEventListener('DOMContentLoaded', function() {
            const modal = document.getElementById('alertModal');
            if (modal) {
                modal.addEventListener('click', function(e) {
                    if (e.target === this) {
                        closeModal();
                    }
                });
            }
        });
    </script>
</body>
</html>
