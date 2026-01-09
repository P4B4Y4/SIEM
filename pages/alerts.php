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
$severity = isset($_GET['severity']) ? $_GET['severity'] : '';
$status = isset($_GET['status']) ? $_GET['status'] : '';
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

// Build query
$query = "SELECT * FROM security_alerts WHERE 1=1";
$count_query = "SELECT COUNT(*) as total FROM security_alerts WHERE 1=1";

if ($severity) {
    $severity = $db->real_escape_string($severity);
    $query .= " AND severity = '$severity'";
    $count_query .= " AND severity = '$severity'";
}

if ($status) {
    $status = $db->real_escape_string($status);
    $query .= " AND status = '$status'";
    $count_query .= " AND status = '$status'";
}

$query .= " ORDER BY timestamp DESC LIMIT $limit OFFSET $offset";

// Get total count
$count_result = $db->query($count_query);
$count_row = $count_result->fetch_assoc();
$totalAlerts = $count_row['total'];
$totalPages = ceil($totalAlerts / $limit);

// Get alerts
$result = $db->query($query);
$alerts = [];
while ($row = $result->fetch_assoc()) {
    $row['details'] = json_decode($row['details'], true);
    $row['recommended_actions'] = json_decode($row['recommended_actions'], true);
    $alerts[] = $row;
}

// Handle alert update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $alert_id = $db->real_escape_string($_POST['alert_id']);
    $new_status = $db->real_escape_string($_POST['status']);
    $notes = isset($_POST['notes']) ? $db->real_escape_string($_POST['notes']) : '';
    
    $update_query = "UPDATE security_alerts SET status = '$new_status'";
    if ($notes) {
        $update_query .= ", notes = '$notes'";
    }
    $update_query .= " WHERE alert_id = '$alert_id'";
    
    if ($db->query($update_query)) {
        // Log to history
        $user_name = $db->real_escape_string($user['username']);
        $action = "Status changed to $new_status";
        $db->query("INSERT INTO alert_history (alert_id, action, user, notes) VALUES ('$alert_id', '$action', '$user_name', '$notes')");
        
        $_SESSION['message'] = 'Alert updated successfully';
        $_SESSION['message_type'] = 'success';
        header('Location: alerts.php' . ($severity ? "?severity=$severity" : '') . ($status ? "&status=$status" : ''));
        exit;
    }
}

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
    <title>Security Alerts - <?php echo APP_NAME; ?></title>
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
        
        .page-header {
            margin-bottom: 30px;
        }
        
        .page-header h1 {
            font-size: 32px;
            margin-bottom: 5px;
        }
        
        .page-header p {
            color: #999;
            font-size: 14px;
        }
        
        .filters {
            background: white;
            padding: 20px;
            border-radius: 5px;
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
        
        .alerts-table {
            background: white;
            border-radius: 5px;
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
        
        .alert-title {
            font-weight: 600;
            color: #333;
        }
        
        .alert-time {
            color: #999;
            font-size: 12px;
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
        
        .pagination {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 5px;
        }
        
        .pagination a,
        .pagination span {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 3px;
            text-decoration: none;
            color: #667eea;
            font-size: 13px;
        }
        
        .pagination a:hover {
            background: #667eea;
            color: white;
        }
        
        .pagination span {
            background: #667eea;
            color: white;
            border-color: #667eea;
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
            max-width: 600px;
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
        
        .alert-details {
            margin-bottom: 20px;
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
        }
        
        .actions-list {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .actions-list li {
            margin-bottom: 8px;
            color: #666;
            font-size: 13px;
        }
        
        .actions-list li:before {
            content: "→ ";
            color: #667eea;
            font-weight: bold;
            margin-right: 8px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #666;
            font-size: 13px;
        }
        
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 13px;
            font-family: inherit;
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 80px;
        }
        
        .btn-submit {
            background: #667eea;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }
        
        .btn-submit:hover {
            background: #5568d3;
        }
        
        .message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 13px;
        }
        
        .message.success {
            background: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        
        .message.error {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        .stat-label {
            color: #999;
            font-size: 12px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 600;
            color: #667eea;
        }
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar">
        <div class="navbar-brand">
            <i class="fas fa-bell"></i>
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
                <div style="color: #999;">Administrator</div>
            </div>
            <a href="?logout=1" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <div class="page-header">
            <h1>Security Alerts</h1>
            <p>View and manage security alerts from threat detection engine</p>
        </div>

        <?php if (isset($_SESSION['message'])): ?>
            <div class="message <?php echo $_SESSION['message_type']; ?>">
                <?php echo $_SESSION['message']; ?>
            </div>
            <?php unset($_SESSION['message']); unset($_SESSION['message_type']); ?>
        <?php endif; ?>

        <!-- Filters -->
        <div class="filters">
            <form method="GET" action="" style="display: flex; gap: 15px; align-items: flex-end; width: 100%;">
                <div class="filter-group">
                    <label for="severity">Severity</label>
                    <select id="severity" name="severity">
                        <option value="">All Severities</option>
                        <option value="critical" <?php echo $severity === 'critical' ? 'selected' : ''; ?>>Critical</option>
                        <option value="high" <?php echo $severity === 'high' ? 'selected' : ''; ?>>High</option>
                        <option value="medium" <?php echo $severity === 'medium' ? 'selected' : ''; ?>>Medium</option>
                        <option value="low" <?php echo $severity === 'low' ? 'selected' : ''; ?>>Low</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="status">Status</label>
                    <select id="status" name="status">
                        <option value="">All Statuses</option>
                        <option value="new" <?php echo $status === 'new' ? 'selected' : ''; ?>>New</option>
                        <option value="acknowledged" <?php echo $status === 'acknowledged' ? 'selected' : ''; ?>>Acknowledged</option>
                        <option value="resolved" <?php echo $status === 'resolved' ? 'selected' : ''; ?>>Resolved</option>
                    </select>
                </div>
                <button type="submit" class="btn-filter">
                    <i class="fas fa-filter"></i> Filter
                </button>
            </form>
        </div>

        <!-- Alerts Table -->
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
                                <td>
                                    <div class="alert-title"><?php echo htmlspecialchars($alert['title']); ?></div>
                                    <div class="alert-time"><?php echo htmlspecialchars($alert['category']); ?></div>
                                </td>
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
                                        <i class="fas fa-eye"></i> View
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

        <!-- Pagination -->
        <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?>
                    <a href="?page=1<?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">
                        <i class="fas fa-chevron-left"></i> First
                    </a>
                    <a href="?page=<?php echo $page - 1; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">
                        Previous
                    </a>
                <?php endif; ?>

                <?php for ($i = max(1, $page - 2); $i <= min($totalPages, $page + 2); $i++): ?>
                    <?php if ($i === $page): ?>
                        <span><?php echo $i; ?></span>
                    <?php else: ?>
                        <a href="?page=<?php echo $i; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <a href="?page=<?php echo $page + 1; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">
                        Next
                    </a>
                    <a href="?page=<?php echo $totalPages; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">
                        Last <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- Stats -->
        <div style="margin-top: 30px; text-align: center; color: #999; font-size: 13px;">
            Showing <?php echo count($alerts); ?> of <?php echo number_format($totalAlerts); ?> alerts
        </div>
    </div>

    <!-- Alert Details Modal -->
    <div id="alertModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Alert Details</h2>
                <button class="btn-close" onclick="closeModal()">&times;</button>
            </div>
            <div id="alertContent"></div>
        </div>
    </div>

    <script>
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return String(text).replace(/[&<>"']/g, m => map[m]);
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
                            <div class="alert-details">
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
                                    <div class="detail-label">User:</div>
                                    <div class="detail-value">${escapeHtml(alert.details ? alert.details.user : 'N/A')}</div>
                                </div>
                                <div class="detail-row">
                                    <div class="detail-label">Description:</div>
                                    <div class="detail-value">${escapeHtml(alert.description)}</div>
                                </div>
                            </div>
                            
                            <h3 style="margin-top: 20px; margin-bottom: 10px;">Recommended Actions</h3>
                            <ul class="actions-list">
                                ${(alert.recommended_actions || []).map(action => `<li>${escapeHtml(action)}</li>`).join('')}
                            </ul>
                            
                            <form method="POST" style="margin-top: 20px;">
                                <input type="hidden" name="alert_id" value="${escapeHtml(alert.alert_id)}">
                                <input type="hidden" name="action" value="update">
                                
                                <div class="form-group">
                                    <label for="status">Update Status:</label>
                                    <select name="status" id="status">
                                        <option value="new" ${alert.status === 'new' ? 'selected' : ''}>New</option>
                                        <option value="acknowledged" ${alert.status === 'acknowledged' ? 'selected' : ''}>Acknowledged</option>
                                        <option value="resolved" ${alert.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label for="notes">Notes:</label>
                                    <textarea name="notes" id="notes" placeholder="Add investigation notes...">${escapeHtml(alert.notes || '')}</textarea>
                                </div>
                                
                                <button type="submit" class="btn-submit">
                                    <i class="fas fa-save"></i> Update Alert
                                </button>
                            </form>
                        `;
                        
                        document.getElementById('alertContent').innerHTML = html;
                        document.getElementById('alertModal').classList.add('active');
                    })
                    .catch(e => {
                        console.error('Error loading alert:', e);
                        document.getElementById('alertContent').innerHTML = '<p style="color: red;">Error loading alert details. Please try again.</p>';
                        document.getElementById('alertModal').classList.add('active');
                    });
            } catch (e) {
                console.error('Error:', e);
                alert('Error loading alert details');
            }
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
