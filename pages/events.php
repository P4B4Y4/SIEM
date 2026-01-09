<?php
/**
 * Events Page
 * Display and filter security events
 */

session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Ensure logs directory exists
if (function_exists('ensureDirectory') && defined('LOG_DIR')) {
    ensureDirectory(LOG_DIR);
}

// Check authentication
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user = ['username' => $_SESSION['username'] ?? 'Admin', 'role' => 'user'];
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);

// Get filter parameters
$view = 'raw';
$severity = $_GET['severity'] ?? '';
$event_type = $_GET['event_type'] ?? '';
$search = $_GET['search'] ?? '';
$page = (int)($_GET['page'] ?? 1);
$limit = 20;
$offset = ($page - 1) * $limit;

// Build query
$where = "WHERE 1=1";
if ($severity) {
    $where .= " AND severity = '" . $db->real_escape_string(strtolower($severity)) . "'";
}
if ($event_type) {
    if ($view === 'normalized') {
        $where .= " AND event_category LIKE '%" . $db->real_escape_string($event_type) . "%'";
    } else {
        $where .= " AND event_type LIKE '%" . $db->real_escape_string($event_type) . "%'";
    }
}
if ($search) {
    if ($view === 'normalized') {
        $where .= " AND (event_category LIKE '%" . $db->real_escape_string($search) . "%'";
        $where .= " OR message LIKE '%" . $db->real_escape_string($search) . "%'";
        $where .= " OR src_ip LIKE '%" . $db->real_escape_string($search) . "%'";
        $where .= " OR dst_ip LIKE '%" . $db->real_escape_string($search) . "%')";
    } else {
        $where .= " AND (event_type LIKE '%" . $db->real_escape_string($search) . "%' OR source_ip LIKE '%" . $db->real_escape_string($search) . "%')";
    }
}

// Get total count
$table = ($view === 'normalized') ? 'normalized_events' : 'security_events';
$countResult = $db->query("SELECT COUNT(*) as total FROM $table $where");
$totalEvents = $countResult ? $countResult->fetch_assoc()['total'] : 0;
$totalPages = ceil($totalEvents / $limit);

// Get events
$orderBy = ($view === 'normalized') ? 'event_time' : 'timestamp';
$result = $db->query("
    SELECT * FROM $table
    $where
    ORDER BY $orderBy DESC
    LIMIT $limit OFFSET $offset
");
$events = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Events - <?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #333;
        }

        .navbar {
            background: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 0 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 70px;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .navbar-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 20px;
            font-weight: 600;
            color: #667eea;
        }

        .navbar-menu {
            display: flex;
            gap: 30px;
            align-items: center;
        }

        .navbar-menu a {
            color: #666;
            text-decoration: none;
            font-size: 14px;
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
            padding: 8px 16px;
            background: #ff6b6b;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }

        .page-header {
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;
        }

        .page-header h1 {
            font-size: 32px;
            margin-bottom: 5px;
        }

        .filters {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }

        .filter-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
        }

        .filter-group label {
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 5px;
            color: #666;
        }

        .filter-group input,
        .filter-group select {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 13px;
        }

        .filter-group input:focus,
        .filter-group select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .filter-buttons {
            display: flex;
            gap: 10px;
        }

        .btn-filter {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }

        .btn-filter:hover {
            background: #5568d3;
        }

        .btn-reset {
            padding: 10px 20px;
            background: #f0f0f0;
            color: #666;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
        }

        .events-table {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead {
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }

        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            color: #666;
            text-transform: uppercase;
        }

        td {
            padding: 15px;
            border-bottom: 1px solid #e9ecef;
            font-size: 13px;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }

        .severity-critical {
            background: #ffe7e7;
            color: #ff6b6b;
        }

        .severity-high {
            background: #fff3e7;
            color: #ffa500;
        }

        .severity-medium {
            background: #e7f0ff;
            color: #667eea;
        }

        .severity-low {
            background: #e7ffe7;
            color: #51cf66;
        }

        .severity-info {
            background: #e7f5ff;
            color: #1971c2;
        }

        .ip-address {
            font-family: monospace;
            font-size: 12px;
        }

        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 30px;
        }

        .pagination a,
        .pagination span {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-decoration: none;
            color: #667eea;
            font-size: 13px;
        }

        .pagination a:hover {
            background: #667eea;
            color: white;
        }

        .pagination .active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }

        .empty-state i {
            font-size: 48px;
            margin-bottom: 15px;
            opacity: 0.5;
        }

        @media (max-width: 768px) {
            .filter-row {
                grid-template-columns: 1fr;
            }

            table {
                font-size: 12px;
            }

            th, td {
                padding: 10px;
            }
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
            <a href="events.php" class="active"><i class="fas fa-list"></i> Events</a>
            <a href="threats.php"><i class="fas fa-exclamation-triangle"></i> Threats & Alerts</a>
            <a href="remote-terminal.php"><i class="fas fa-terminal"></i> Remote Terminal</a>
            <a href="task-manager.php"><i class="fas fa-tasks"></i> Task Manager</a>
            <a href="settings.php"><i class="fas fa-cog"></i> Settings</a>
        </div>
        <div class="user-menu">
            <div style="text-align: right; font-size: 13px;">
                <div style="font-weight: 600; color: #333;"><?php echo escape($user['username']); ?></div>
                <div style="color: #999;"><?php echo escape(ucfirst($user['role'])); ?></div>
            </div>
            <a href="?logout=1" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <div class="page-header">
            <div>
                <h1>Security Events</h1>
                <p>View and filter all security events from your systems</p>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <label for="autoRefresh" style="font-size: 13px; color: #666;">Auto-refresh:</label>
                <select id="autoRefresh" style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px;">
                    <option value="0">Off</option>
                    <option value="5">5 seconds</option>
                    <option value="10" selected>10 seconds</option>
                    <option value="30">30 seconds</option>
                    <option value="60">1 minute</option>
                </select>
                <button id="refreshBtn" style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 13px;">
                    <i class="fas fa-sync-alt"></i> Refresh Now
                </button>
            </div>
        </div>

        <!-- Filters -->
        <div class="filters">
            <form method="GET" action="">
                <div class="filter-row">
                    <div class="filter-group">
                        <label for="view">View</label>
                        <select id="view" name="view">
                            <option value="raw" <?php echo $view === 'raw' ? 'selected' : ''; ?>>Raw Events</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="search">Search</label>
                        <input type="text" id="search" name="search" placeholder="Event type or IP address" value="<?php echo escape($search); ?>">
                    </div>
                    <div class="filter-group">
                        <label for="severity">Severity</label>
                        <select id="severity" name="severity">
                            <option value="">All Severities</option>
                            <option value="critical" <?php echo $severity === 'critical' ? 'selected' : ''; ?>>Critical</option>
                            <option value="high" <?php echo $severity === 'high' ? 'selected' : ''; ?>>High</option>
                            <option value="medium" <?php echo $severity === 'medium' ? 'selected' : ''; ?>>Medium</option>
                            <option value="low" <?php echo $severity === 'low' ? 'selected' : ''; ?>>Low</option>
                            <option value="info" <?php echo $severity === 'info' ? 'selected' : ''; ?>>Info</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="event_type">Event Type</label>
                        <input type="text" id="event_type" name="event_type" placeholder="Filter by event type" value="<?php echo escape($event_type); ?>">
                    </div>
                </div>
                <div class="filter-buttons">
                    <button type="submit" class="btn-filter">
                        <i class="fas fa-search"></i> Filter
                    </button>
                    <a href="events.php" class="btn-reset">
                        <i class="fas fa-redo"></i> Reset
                    </a>
                </div>
            </form>
        </div>

        <!-- Events Table -->
        <div class="events-table">
            <?php if (empty($events)): ?>
                <div class="empty-state">
                    <i class="fas fa-inbox"></i>
                    <p>No events found</p>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Event Type</th>
                            <th>Severity</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Protocol</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($events as $event): ?>
                            <tr>
                                <td>
                                    <?php
                                    $ts = ($view === 'normalized') ? ($event['event_time'] ?? null) : ($event['timestamp'] ?? null);
                                    echo $ts ? date('M d, Y H:i:s', strtotime($ts)) : '-';
                                    ?>
                                </td>
                                <td>
                                    <?php
                                    $type = ($view === 'normalized') ? ($event['event_category'] ?? 'Unknown') : ($event['event_type'] ?? 'Unknown');
                                    echo escape($type);
                                    ?>
                                </td>
                                <td>
                                    <span class="severity-badge severity-<?php echo strtolower($event['severity'] ?? 'info'); ?>">
                                        <?php echo ucfirst($event['severity'] ?? 'Info'); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="ip-address">
                                        <?php echo escape(($view === 'normalized') ? ($event['src_ip'] ?? '-') : ($event['source_ip'] ?? '-')); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="ip-address">
                                        <?php echo escape(($view === 'normalized') ? ($event['dst_ip'] ?? '-') : ($event['dest_ip'] ?? '-')); ?>
                                    </span>
                                </td>
                                <td><?php echo escape(($view === 'normalized') ? ($event['network_protocol'] ?? '-') : ($event['protocol'] ?? '-')); ?></td>
                                <td>
                                    <?php $id = ($view === 'normalized') ? ($event['id'] ?? 0) : ($event['event_id'] ?? 0); ?>
                                    <a href="event-details.php?view=<?php echo urlencode($view); ?>&id=<?php echo (int)$id; ?>" style="color: #667eea; text-decoration: none;">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Pagination -->
        <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?>
                    <a href="?page=1&view=<?php echo urlencode($view); ?>&severity=<?php echo urlencode($severity); ?>&event_type=<?php echo urlencode($event_type); ?>&search=<?php echo urlencode($search); ?>">
                        <i class="fas fa-chevron-left"></i> First
                    </a>
                    <a href="?page=<?php echo $page - 1; ?>&view=<?php echo urlencode($view); ?>&severity=<?php echo urlencode($severity); ?>&event_type=<?php echo urlencode($event_type); ?>&search=<?php echo urlencode($search); ?>">
                        Previous
                    </a>
                <?php endif; ?>

                <?php for ($i = max(1, $page - 2); $i <= min($totalPages, $page + 2); $i++): ?>
                    <?php if ($i === $page): ?>
                        <span class="active"><?php echo $i; ?></span>
                    <?php else: ?>
                        <a href="?page=<?php echo $i; ?>&view=<?php echo urlencode($view); ?>&severity=<?php echo urlencode($severity); ?>&event_type=<?php echo urlencode($event_type); ?>&search=<?php echo urlencode($search); ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <a href="?page=<?php echo $page + 1; ?>&view=<?php echo urlencode($view); ?>&severity=<?php echo urlencode($severity); ?>&event_type=<?php echo urlencode($event_type); ?>&search=<?php echo urlencode($search); ?>">
                        Next
                    </a>
                    <a href="?page=<?php echo $totalPages; ?>&view=<?php echo urlencode($view); ?>&severity=<?php echo urlencode($severity); ?>&event_type=<?php echo urlencode($event_type); ?>&search=<?php echo urlencode($search); ?>">
                        Last <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- Stats -->
        <div style="margin-top: 30px; text-align: center; color: #999; font-size: 13px;">
            Showing <?php echo count($events); ?> of <?php echo number_format($totalEvents); ?> events
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;
        let refreshTimeout = null;

        // Get current URL parameters
        function getCurrentUrl() {
            const params = new URLSearchParams(window.location.search);
            let url = window.location.pathname + '?';
            
            if (params.get('severity')) url += 'severity=' + encodeURIComponent(params.get('severity')) + '&';
            if (params.get('event_type')) url += 'event_type=' + encodeURIComponent(params.get('event_type')) + '&';
            if (params.get('search')) url += 'search=' + encodeURIComponent(params.get('search')) + '&';
            if (params.get('page')) url += 'page=' + params.get('page') + '&';
            
            return url.slice(0, -1); // Remove trailing &
        }

        // Refresh page
        function refreshPage() {
            window.location.href = getCurrentUrl();
        }

        // Setup auto-refresh
        function setupAutoRefresh() {
            const interval = parseInt(document.getElementById('autoRefresh').value);
            
            // Clear existing interval
            if (autoRefreshInterval) clearInterval(autoRefreshInterval);
            if (refreshTimeout) clearTimeout(refreshTimeout);
            
            if (interval > 0) {
                autoRefreshInterval = setInterval(refreshPage, interval * 1000);
                console.log('Auto-refresh enabled: ' + interval + ' seconds');
            } else {
                console.log('Auto-refresh disabled');
            }
        }

        // Event listeners
        document.getElementById('autoRefresh').addEventListener('change', setupAutoRefresh);
        document.getElementById('refreshBtn').addEventListener('click', refreshPage);

        // Initialize on page load
        window.addEventListener('load', setupAutoRefresh);

        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            if (autoRefreshInterval) clearInterval(autoRefreshInterval);
        });
    </script>
    
    <?php
    // Handle logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit;
    }
    ?>
</body>
</html>
