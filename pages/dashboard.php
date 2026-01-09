<?php
/**
 * Dashboard Page
 * Main application dashboard with statistics and overview
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

// Get user info
$user = [
    'username' => $_SESSION['username'] ?? 'Admin',
    'role' => 'Administrator'
];

// Get statistics
$total_events = $db->query("SELECT COUNT(*) as count FROM security_events")->fetch_assoc()['count'] ?? 0;
$critical_alerts = $db->query("SELECT COUNT(*) as count FROM security_events WHERE severity = 'critical'")->fetch_assoc()['count'] ?? 0;
$high_alerts = $db->query("SELECT COUNT(*) as count FROM security_events WHERE severity = 'high'")->fetch_assoc()['count'] ?? 0;
$active_agents = $db->query("SELECT COUNT(DISTINCT source_ip) as count FROM security_events WHERE timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)")->fetch_assoc()['count'] ?? 0;

$stats = [
    'total_events' => $total_events,
    'critical_alerts' => $critical_alerts,
    'high_alerts' => $high_alerts,
    'active_agents' => $active_agents
];

// Get recent events
$recentEvents = $db->query("
    SELECT timestamp, event_type, severity, source_ip, raw_log 
    FROM security_events 
    ORDER BY timestamp DESC 
    LIMIT 5
")->fetch_all(MYSQLI_ASSOC) ?? [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - JFS ICT Services SIEM</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
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

        .navbar-brand i {
            font-size: 28px;
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

        .navbar-menu a:hover {
            color: #667eea;
        }

        .user-menu {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .user-info {
            text-align: right;
            font-size: 13px;
        }

        .user-info .username {
            font-weight: 600;
            color: #333;
        }

        .user-info .role {
            color: #999;
            font-size: 12px;
        }

        .btn-logout {
            padding: 8px 16px;
            background: #ff6b6b;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            transition: background 0.3s;
        }

        .btn-logout:hover {
            background: #ff5252;
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

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
        }

        .stat-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .stat-card-title {
            font-size: 14px;
            color: #999;
            font-weight: 500;
        }

        .stat-card-icon {
            font-size: 24px;
            width: 50px;
            height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
        }

        .stat-card-icon.primary {
            background: #e7f0ff;
            color: #667eea;
        }

        .stat-card-icon.danger {
            background: #ffe7e7;
            color: #ff6b6b;
        }

        .stat-card-icon.warning {
            background: #fff3e7;
            color: #ffa500;
        }

        .stat-card-icon.success {
            background: #e7ffe7;
            color: #51cf66;
        }

        .stat-card-value {
            font-size: 32px;
            font-weight: 700;
            color: #333;
            margin-bottom: 5px;
        }

        .stat-card-change {
            font-size: 12px;
            color: #999;
        }

        .content-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
        }

        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 25px;
        }

        .chart-wrap {
            position: relative;
            height: 260px;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #f0f0f0;
        }

        .card-title {
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }

        .card-action {
            color: #667eea;
            text-decoration: none;
            font-size: 13px;
            cursor: pointer;
        }

        .card-action:hover {
            text-decoration: underline;
        }

        .event-item {
            padding: 15px 0;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            gap: 15px;
            align-items: flex-start;
        }

        .event-item:last-child {
            border-bottom: none;
        }

        .event-icon {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            font-size: 18px;
        }

        .event-icon.critical {
            background: #ffe7e7;
            color: #ff6b6b;
        }

        .event-icon.high {
            background: #fff3e7;
            color: #ffa500;
        }

        .event-icon.medium {
            background: #e7f0ff;
            color: #667eea;
        }

        .event-icon.low {
            background: #e7ffe7;
            color: #51cf66;
        }

        .event-content {
            flex: 1;
        }

        .risk-item {
            display: flex;
            gap: 12px;
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
            align-items: flex-start;
        }
        .risk-item:last-child { border-bottom: none; }
        .risk-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            font-size: 16px;
            background: #f6f7ff;
            color: #667eea;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }
        .badge.critical { background: #ffe7e7; color: #c91818; }
        .badge.high { background: #fff3e7; color: #b35a00; }
        .badge.medium { background: #e7f0ff; color: #2f5fb3; }
        .badge.low { background: #e7ffe7; color: #167a2f; }
        .risk-title { font-weight: 700; margin-bottom: 4px; }
        .risk-meta { font-size: 12px; color: #777; margin-bottom: 6px; }
        .risk-reason { font-size: 12px; color: #333; background: #fafafa; border: 1px solid #eee; padding: 8px; border-radius: 8px; }

        .event-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 3px;
        }

        .event-time {
            font-size: 12px;
            color: #999;
        }

        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #999;
        }

        .empty-state i {
            font-size: 48px;
            margin-bottom: 15px;
            opacity: 0.5;
        }

        .ai-box {
            padding: 12px;
            border: 1px dashed #ddd;
            border-radius: 8px;
            background: #fafafa;
            font-size: 13px;
            color: #333;
            line-height: 1.4;
        }

        @media (max-width: 768px) {
            .content-grid {
                grid-template-columns: 1fr;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .navbar {
                flex-direction: column;
                height: auto;
                padding: 15px 20px;
                gap: 15px;
            }

            .navbar-menu {
                width: 100%;
                justify-content: space-between;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar">
        <div class="navbar-brand">
            <i class="fas fa-shield-alt"></i>
            <span>JFS ICT SIEM</span>
        </div>
        <div class="navbar-menu">
            <a href="dashboard.php" class="active"><i class="fas fa-home"></i> Dashboard</a>
            <a href="events.php"><i class="fas fa-list"></i> Events</a>
            <a href="threats.php"><i class="fas fa-exclamation-triangle"></i> Threats & Alerts</a>
            <a href="remote-terminal.php"><i class="fas fa-terminal"></i> Remote Terminal</a>
            <a href="task-manager.php"><i class="fas fa-tasks"></i> Task Manager</a>
            <a href="settings.php"><i class="fas fa-cog"></i> Settings</a>
        </div>
        <div class="user-menu">
            <div class="user-info">
                <div class="username"><?php echo htmlspecialchars($user['username']); ?></div>
                <div class="role"><?php echo htmlspecialchars(ucfirst($user['role'])); ?></div>
            </div>
            <a href="?logout=1" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <div class="page-header">
            <h1>Welcome, <?php echo htmlspecialchars($user['username']); ?>!</h1>
            <p>Security Operations Center Dashboard</p>
        </div>

        <!-- Statistics Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-card-header">
                    <div class="stat-card-title">Total Events</div>
                    <div class="stat-card-icon primary">
                        <i class="fas fa-chart-line"></i>
                    </div>
                </div>
                <div class="stat-card-value"><?php echo number_format($stats['total_events']); ?></div>
                <div class="stat-card-change">All security events</div>
            </div>

            <div class="stat-card">
                <div class="stat-card-header">
                    <div class="stat-card-title">Critical Alerts</div>
                    <div class="stat-card-icon danger">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                </div>
                <div class="stat-card-value"><?php echo number_format($stats['critical_alerts']); ?></div>
                <div class="stat-card-change">Requires immediate action</div>
            </div>

            <div class="stat-card">
                <div class="stat-card-header">
                    <div class="stat-card-title">High Alerts</div>
                    <div class="stat-card-icon warning">
                        <i class="fas fa-alert"></i>
                    </div>
                </div>
                <div class="stat-card-value"><?php echo number_format($stats['high_alerts']); ?></div>
                <div class="stat-card-change">Monitor closely</div>
            </div>

            <div class="stat-card">
                <div class="stat-card-header">
                    <div class="stat-card-title">Active Agents</div>
                    <div class="stat-card-icon success">
                        <i class="fas fa-server"></i>
                    </div>
                </div>
                <div class="stat-card-value"><?php echo number_format($stats['active_agents']); ?></div>
                <div class="stat-card-change">Connected and reporting</div>
            </div>
        </div>

        <!-- Content Grid -->
        <div class="content-grid">
            <!-- Trends -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Last 24 Hours Trend</div>
                </div>
                <div class="chart-wrap">
                    <canvas id="eventsTrendChart"></canvas>
                </div>
                <div id="trendMeta" style="margin-top:10px; font-size:12px; color:#666;"></div>
            </div>

            <!-- Recent Events -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Recent Events</div>
                    <a href="events.php" class="card-action">View All</a>
                </div>
                <div class="events-list">
                    <?php if (empty($recentEvents)): ?>
                        <div class="empty-state">
                            <i class="fas fa-inbox"></i>
                            <p>No events yet</p>
                        </div>
                    <?php else: ?>
                        <?php foreach ($recentEvents as $event): ?>
                            <div class="event-item">
                                <div class="event-icon <?php echo strtolower($event['severity'] ?? 'low'); ?>">
                                    <i class="fas fa-shield-alt"></i>
                                </div>
                                <div class="event-content">
                                    <div class="event-title"><?php echo htmlspecialchars($event['event_type'] ?? 'Unknown'); ?></div>
                                    <div class="event-time"><?php echo htmlspecialchars($event['timestamp'] ?? date('Y-m-d H:i:s')); ?></div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Top Risky Activity -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Top 5 Risky Activity</div>
                    <a href="#" id="riskyRefresh" class="card-action">Refresh</a>
                </div>
                <div id="topRiskyList">
                    <div class="empty-state" style="padding:20px 0;">
                        <p>Loading...</p>
                    </div>
                </div>
                <div id="topRiskyMeta" style="margin-top:10px; font-size:12px; color:#666;"></div>
            </div>

            <!-- Quick Stats -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">System Status</div>
                </div>
                <div style="padding: 20px 0;">
                    <div style="margin-bottom: 20px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <span style="font-size: 14px; color: #666;">Database</span>
                            <span style="font-size: 14px; color: #51cf66; font-weight: 600;">Connected</span>
                        </div>
                        <div style="height: 6px; background: #f0f0f0; border-radius: 3px; overflow: hidden;">
                            <div style="height: 100%; background: #51cf66; width: 100%;"></div>
                        </div>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <span style="font-size: 14px; color: #666;">API Health</span>
                            <span style="font-size: 14px; color: #51cf66; font-weight: 600;">Healthy</span>
                        </div>
                        <div style="height: 6px; background: #f0f0f0; border-radius: 3px; overflow: hidden;">
                            <div style="height: 100%; background: #51cf66; width: 100%;"></div>
                        </div>
                    </div>

                    <div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <span style="font-size: 14px; color: #666;">Collectors</span>
                            <span style="font-size: 14px; color: #51cf66; font-weight: 600;">Active</span>
                        </div>
                        <div style="height: 6px; background: #f0f0f0; border-radius: 3px; overflow: hidden;">
                            <div style="height: 100%; background: #51cf66; width: 100%;"></div>
                        </div>
                    </div>
                </div>
            </div>
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

    <script>
        (function() {
            const ctx = document.getElementById('eventsTrendChart');
            const meta = document.getElementById('trendMeta');
            const riskyList = document.getElementById('topRiskyList');
            const riskyMeta = document.getElementById('topRiskyMeta');
            const riskyRefresh = document.getElementById('riskyRefresh');

            function escapeHtml(str) {
                return String(str)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#039;');
            }

            function safeText(s) {
                return escapeHtml(String(s || ''));
            }

            function sevClass(sev) {
                const s = String(sev || '').toLowerCase();
                if (s === 'critical') return 'critical';
                if (s === 'high') return 'high';
                if (s === 'medium') return 'medium';
                return 'low';
            }

            function iconFor(type) {
                return type === 'alert' ? 'fa-exclamation-triangle' : 'fa-bolt';
            }

            function renderRisky(items) {
                if (!riskyList) return;
                if (!Array.isArray(items) || items.length === 0) {
                    riskyList.innerHTML = '<div class="empty-state" style="padding:20px 0;"><p>No risky activity found</p></div>';
                    return;
                }
                riskyList.innerHTML = items.map((it) => {
                    const type = it.type || '';
                    const sev = sevClass(it.severity);
                    const title = it.title || '';
                    const desc = it.description || '';
                    const host = it.host || '';
                    const ts = it.timestamp || '';
                    const reason = it.reason || '';
                    const typeLabel = type === 'alert' ? 'ALERT' : 'EVENT';
                    const link = (type === 'alert')
                        ? 'threats.php'
                        : 'event-details.php?event_id=' + encodeURIComponent(String(it.id || ''));
                    const oneLine = (reason || desc) ? `<div class="risk-meta" style="margin-top:2px; color:#444;">${safeText(reason || desc)}</div>` : '';
                    return `
                        <div class="risk-item">
                            <div class="risk-icon"><i class="fas ${iconFor(type)}"></i></div>
                            <div style="flex:1;">
                                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                                    <div class="risk-title">${safeText(title)}</div>
                                    <span class="badge ${sev}">${safeText(typeLabel)} • ${safeText(sev.toUpperCase())}</span>
                                </div>
                                <div class="risk-meta">${host ? ('Host: ' + safeText(host) + ' • ') : ''}${ts ? ('Time: ' + safeText(ts)) : ''}</div>
                                ${oneLine}
                                <div style="margin-top:8px;">
                                    <a class="card-action" href="${link}">View</a>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');
            }

            function loadRisky(force) {
                if (riskyList) {
                    riskyList.innerHTML = '<div class="empty-state" style="padding:20px 0;"><p>Loading...</p></div>';
                }
                if (riskyMeta) {
                    riskyMeta.textContent = '';
                }
                const url = '../api/ai-top-risky.php' + (force ? '?force=1' : '');
                fetch(url)
                    .then(async (r) => {
                        const text = await r.text();
                        let data;
                        try { data = JSON.parse(text); } catch (e) {
                            throw new Error('Invalid JSON from ai-top-risky.php: ' + (text ? text.substring(0, 200) : '[empty]'));
                        }
                        if (!data.success) throw new Error(data.error || 'Failed to load risky items');
                        return data;
                    })
                    .then(data => {
                        renderRisky(Array.isArray(data.items) ? data.items : []);
                        if (riskyMeta) {
                            const cached = data.cached ? 'cached' : 'fresh';
                            const updated = data.updated_at ? (' • updated ' + String(data.updated_at)) : '';
                            riskyMeta.textContent = 'Top 5 risky alerts/events • ' + cached + updated;
                        }
                    })
                    .catch(err => {
                        if (riskyList) {
                            riskyList.innerHTML = '<div class="empty-state" style="padding:20px 0;"><p style="color:#b00020;">Error: ' + safeText(err.message || err) + '</p></div>';
                        }
                    });
            }

            loadRisky(false);
            if (riskyRefresh) {
                riskyRefresh.addEventListener('click', function(e) {
                    e.preventDefault();
                    loadRisky(true);
                });
            }

            // Auto-refresh Top 5 Risky Activity (every 5 minutes) when tab is visible
            setInterval(() => {
                if (document.hidden) return;
                loadRisky(true);
            }, 5 * 60 * 1000);

            if (!ctx) return;

            fetch('../api/dashboard-stats.php')
                .then(async (r) => {
                    const text = await r.text();
                    let data;
                    try { data = JSON.parse(text); } catch (e) {
                        throw new Error('Invalid JSON from dashboard-stats.php: ' + (text ? text.substring(0, 200) : '[empty]'));
                    }
                    if (!data.success) throw new Error(data.error || 'Failed to load stats');
                    return data;
                })
                .then(data => {
                    const labels = Array.isArray(data.labels) ? data.labels : [];
                    const events = Array.isArray(data.events) ? data.events : [];
                    const alerts = Array.isArray(data.alerts) ? data.alerts : [];

                    new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels,
                            datasets: [
                                {
                                    label: 'Events',
                                    data: events,
                                    borderColor: '#667eea',
                                    backgroundColor: 'rgba(102,126,234,0.15)',
                                    tension: 0.3,
                                    fill: true,
                                    pointRadius: 2
                                },
                                {
                                    label: 'Alerts',
                                    data: alerts,
                                    borderColor: '#ff6b6b',
                                    backgroundColor: 'rgba(255,107,107,0.12)',
                                    tension: 0.3,
                                    fill: true,
                                    pointRadius: 2
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { display: true } },
                            scales: {
                                y: { beginAtZero: true, ticks: { precision: 0 } }
                            }
                        }
                    });

                    if (meta) {
                        const totalEvents = events.reduce((a,b) => a + (Number(b)||0), 0);
                        const totalAlerts = alerts.reduce((a,b) => a + (Number(b)||0), 0);
                        meta.textContent = 'Last 24h totals: ' + totalEvents + ' events, ' + totalAlerts + ' alerts.';
                    }
                })
                .catch(err => {
                    if (meta) meta.innerHTML = '<span style="color:#b00020;">Trend load error: ' + String(err.message || err) + '</span>';
                });
        })();

        function formatAgo(ts) {
            const t = new Date(ts.replace(' ', 'T'));
            if (isNaN(t.getTime())) return '';
            const diff = Math.max(0, Date.now() - t.getTime());
            const mins = Math.floor(diff / 60000);
            if (mins < 60) return mins + 'm ago';
            const hrs = Math.floor(mins / 60);
            if (hrs < 48) return hrs + 'h ago';
            return Math.floor(hrs / 24) + 'd ago';
        }

        function escapeHtml2(str) {
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        document.addEventListener('DOMContentLoaded', function() {
        });
    </script>
</body>
</html>
