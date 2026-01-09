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
$count_row = $count_result ? $count_result->fetch_assoc() : ['total' => 0];
$totalAlerts = (int)($count_row['total'] ?? 0);
$totalPages = (int)ceil($totalAlerts / $limit);

// Get alerts
$result = $db->query($query);
$alerts = [];
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $row['details'] = json_decode($row['details'], true);
        $row['recommended_actions'] = json_decode($row['recommended_actions'], true);
        $alerts[] = $row;
    }
}

// Get statistics
$total_alerts = $db->query("SELECT COUNT(*) as count FROM security_alerts")->fetch_assoc()['count'] ?? 0;
$critical_alerts = $db->query("SELECT COUNT(*) as count FROM security_alerts WHERE severity = 'critical'")->fetch_assoc()['count'] ?? 0;
$high_alerts = $db->query("SELECT COUNT(*) as count FROM security_alerts WHERE severity = 'high'")->fetch_assoc()['count'] ?? 0;
$total_events = $db->query("SELECT COUNT(*) as count FROM security_events")->fetch_assoc()['count'] ?? 0;

$latest_alert_ts_row = $db->query("SELECT MAX(timestamp) AS max_ts FROM security_alerts") ? $db->query("SELECT MAX(timestamp) AS max_ts FROM security_alerts")->fetch_assoc() : null;
$latest_alert_ts = $latest_alert_ts_row['max_ts'] ?? null;

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
        $user_name = $db->real_escape_string($user['username']);
        $action = "Status changed to $new_status";
        $db->query("INSERT INTO alert_history (alert_id, action, user, notes) VALUES ('$alert_id', '$action', '$user_name', '$notes')");

        header('Location: threats.php' . ($severity ? "?severity=$severity" : '') . ($status ? "&status=$status" : ''));
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
    <title>Threats & Alerts - <?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }
        .navbar { background: white; padding: 15px 30px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .navbar-brand { font-size: 20px; font-weight: 600; color: #667eea; display: flex; align-items: center; gap: 10px; }
        .navbar-menu { display: flex; gap: 30px; }
        .navbar-menu a { text-decoration: none; color: #666; font-size: 14px; display: flex; align-items: center; gap: 8px; transition: color 0.3s; }
        .navbar-menu a:hover, .navbar-menu a.active { color: #667eea; }
        .user-menu { display: flex; align-items: center; gap: 15px; }
        .btn-logout { background: #ef4444; color: white; padding: 8px 16px; border-radius: 5px; text-decoration: none; font-size: 13px; transition: background 0.3s; }
        .btn-logout:hover { background: #dc2626; }
        .container { max-width: 1400px; margin: 0 auto; padding: 30px; }
        .page-title { font-size: 32px; margin-bottom: 20px; color: #333; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-label { color: #999; font-size: 12px; margin-bottom: 8px; text-transform: uppercase; }
        .stat-value { font-size: 32px; font-weight: 600; color: #667eea; }
        .stat-card.critical .stat-value { color: #ef4444; }
        .stat-card.high .stat-value { color: #f59e0b; }

        .filters { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; display: flex; gap: 15px; align-items: flex-end; }
        .filter-group { display: flex; flex-direction: column; gap: 5px; }
        .filter-group label { font-size: 13px; font-weight: 600; color: #666; }
        .filter-group select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 13px; }
        .btn-filter { padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 13px; }
        .btn-filter:hover { background: #5568d3; }

        .alerts-table { background: white; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f9f9f9; padding: 15px; text-align: left; font-size: 13px; font-weight: 600; color: #666; border-bottom: 1px solid #eee; }
        td { padding: 15px; border-bottom: 1px solid #eee; font-size: 13px; }
        tr:hover { background: #f9f9f9; }
        .severity-badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .severity-critical { background: #fee2e2; color: #991b1b; }
        .severity-high { background: #fef3c7; color: #92400e; }
        .severity-medium { background: #dbeafe; color: #1e40af; }
        .severity-low { background: #dcfce7; color: #166534; }
        .status-badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
        .status-new { background: #e0e7ff; color: #3730a3; }
        .status-acknowledged { background: #fef3c7; color: #92400e; }
        .status-resolved { background: #dcfce7; color: #166534; }
        .btn-view { background: #667eea; color: white; padding: 6px 12px; border: none; border-radius: 3px; cursor: pointer; font-size: 12px; }
        .btn-view:hover { background: #5568d3; }

        .pagination { margin-top: 20px; display: flex; justify-content: center; gap: 5px; }
        .pagination a, .pagination span { padding: 8px 12px; border: 1px solid #ddd; border-radius: 3px; text-decoration: none; color: #667eea; font-size: 13px; }
        .pagination a:hover { background: #667eea; color: white; }
        .pagination span { background: #667eea; color: white; border-color: #667eea; }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center; }
        .modal.active { display: flex; }
        .modal-content { background: white; padding: 30px; border-radius: 10px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h2 { font-size: 20px; }
        .btn-close { background: none; border: none; font-size: 24px; cursor: pointer; color: #999; }
        .detail-row { display: flex; gap: 20px; margin-bottom: 15px; }
        .detail-label { font-weight: 600; color: #666; min-width: 150px; }
        .detail-value { color: #333; word-break: break-word; }
        .recommendations { background: #f9f9f9; padding: 15px; border-radius: 5px; margin-top: 15px; }
        .recommendations h4 { margin-bottom: 10px; color: #333; }
        .recommendations li { margin-bottom: 8px; color: #666; font-size: 13px; }
        .recommendations li:before { content: "→ "; color: #667eea; font-weight: bold; margin-right: 8px; }

        .ai-card { border: 1px dashed #ddd; border-radius: 10px; background: #fafafa; padding: 12px; margin-top: 12px; }
        .ai-card-header { display:flex; align-items:center; justify-content:space-between; gap:10px; }
        .ai-card-title { font-weight: 800; font-size: 13px; color:#111; display:flex; align-items:center; gap:8px; }
        .ai-badge { display:inline-flex; align-items:center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; border: 1px solid #e5e7eb; background:#fff; color:#4b5563; }
        .ai-meta { font-size: 12px; color: #6b7280; margin-top: 8px; }
        .ai-section { margin-top: 10px; }
        .ai-section-title { font-size: 12px; color: #6b7280; font-weight: 800; text-transform: uppercase; margin-bottom: 6px; display:flex; align-items:center; gap:8px; }
        .ai-text { font-size: 14px; color:#111; line-height: 1.45; white-space: pre-wrap; }
        .ai-list { margin-left: 18px; }
        .ai-list li { margin-bottom: 8px; color:#374151; font-size: 13px; }
        .ai-cmd-list { list-style:none; padding-left: 0; margin: 8px 0 0 0; }
        .ai-cmd-item { display:flex; align-items:flex-start; justify-content:space-between; gap:10px; padding: 10px; border: 1px solid #eee; border-radius: 10px; background:#fff; margin-bottom: 10px; }
        .ai-cmd-left { min-width:0; flex: 1; }
        .ai-cmd-label { font-weight: 800; font-size: 12px; color:#111; }
        .ai-cmd-code { margin-top: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; font-size: 12px; color:#111; background:#f3f4f6; border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px; white-space: pre-wrap; word-break: break-word; }
        .ai-cmd-actions { display:flex; gap: 6px; flex-shrink: 0; }
        .btn-ai { background: #111827; color:#fff; border:none; border-radius: 8px; padding: 7px 10px; font-size: 12px; cursor:pointer; }
        .btn-ai:hover { background: #0b1220; }
        .btn-ai-secondary { background:#667eea; }
        .btn-ai-secondary:hover { background:#5568d3; }
        .btn-ai-link { background: transparent; color:#667eea; border: 1px solid #c7d2fe; border-radius: 8px; padding: 6px 10px; font-size: 12px; cursor:pointer; }
        .btn-ai-link:hover { background:#eef2ff; }

        @media (max-width: 768px) {
            .navbar { flex-direction: column; gap: 15px; }
            .navbar-menu { flex-wrap: wrap; justify-content: center; }
            .filters { flex-direction: column; align-items: stretch; }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-brand">
            <i class="fas fa-exclamation-triangle"></i>
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
            <a href="?logout=1" class="btn-logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>
    </nav>

    <div class="container">
        <h1 class="page-title"><i class="fas fa-exclamation-triangle"></i> Threats & Alerts</h1>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-label">Critical Alerts</div>
                <div class="stat-value"><?php echo (int)$critical_alerts; ?></div>
            </div>
            <div class="stat-card high">
                <div class="stat-label">High Alerts</div>
                <div class="stat-value"><?php echo (int)$high_alerts; ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Alerts</div>
                <div class="stat-value"><?php echo (int)$total_alerts; ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Events</div>
                <div class="stat-value"><?php echo (int)$total_events; ?></div>
            </div>
        </div>

        <div class="filters">
            <form method="GET" action="" style="display: flex; gap: 15px; align-items: flex-end; width: 100%; flex-wrap: wrap;">
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
                <button type="submit" class="btn-filter"><i class="fas fa-filter"></i> Filter</button>
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
                                    <button class="btn-view" onclick="viewAlert('<?php echo htmlspecialchars($alert['alert_id']); ?>')">
                                        <i class="fas fa-eye"></i> View
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="7" style="text-align: center; color: #999; padding: 40px;">No alerts found</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?>
                    <a href="?page=1<?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">
                        <i class="fas fa-chevron-left"></i> First
                    </a>
                    <a href="?page=<?php echo $page - 1; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">Previous</a>
                <?php endif; ?>

                <?php for ($i = max(1, $page - 2); $i <= min($totalPages, $page + 2); $i++): ?>
                    <?php if ($i === $page): ?>
                        <span><?php echo $i; ?></span>
                    <?php else: ?>
                        <a href="?page=<?php echo $i; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>"><?php echo $i; ?></a>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <a href="?page=<?php echo $page + 1; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">Next</a>
                    <a href="?page=<?php echo $totalPages; ?><?php echo $severity ? "&severity=$severity" : ''; ?><?php echo $status ? "&status=$status" : ''; ?>">
                        Last <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div style="margin-top: 30px; text-align: center; color: #999; font-size: 13px;">
            Showing <?php echo count($alerts); ?> of <?php echo number_format($totalAlerts); ?> alerts
        </div>

        <div style="margin-top: 10px; text-align: center; color: #bbb; font-size: 12px;">
            Updated: <?php echo date('Y-m-d H:i:s', filemtime(__FILE__)); ?>
        </div>

        <div style="margin-top: 6px; text-align: center; color: #bbb; font-size: 12px;">
            Latest alert in DB: <?php echo $latest_alert_ts ? htmlspecialchars($latest_alert_ts) : 'N/A'; ?>
        </div>
    </div>

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
        const BASE_PATH = <?php echo json_encode(rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'])), '/\\')); ?>;

        function sendPendingAlertEmails() {
            fetch('../api/send-alert-email.php?action=send_pending&limit=200', {
                method: 'POST'
            })
            .then(r => r.json())
            .then(data => {
                // Silent best-effort; details are in server logs / JSON response.
            })
            .catch(() => {
                // Ignore background errors
            });
        }

        // Auto-send/resend NEW alerts every 30 minutes while this page is open
        sendPendingAlertEmails();
        setInterval(sendPendingAlertEmails, 30 * 60 * 1000);

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

        function setAiLoadingState(loading) {
            const meta = document.getElementById('aiMeta');
            if (!meta) return;
            meta.innerHTML = loading ? '<i class="fas fa-spinner fa-spin"></i> Analyzing...' : meta.innerHTML;
        }

        function toggleOriginal(showOriginal) {
            const aiBox = document.getElementById('aiBox');
            const origDesc = document.getElementById('origDescription');
            const aiDesc = document.getElementById('aiDescription');
            const origActions = document.getElementById('origActions');
            const aiActions = document.getElementById('aiActions');

            if (!origDesc || !origActions) return;

            if (showOriginal) {
                if (aiBox) aiBox.style.display = 'none';
                if (aiDesc) aiDesc.style.display = 'none';
                if (aiActions) aiActions.style.display = 'none';
                origDesc.style.display = '';
                origActions.style.display = '';
            } else {
                if (aiBox) aiBox.style.display = '';
                if (aiDesc) aiDesc.style.display = '';
                if (aiActions) aiActions.style.display = '';
                origDesc.style.display = 'none';
                origActions.style.display = 'none';
            }
        }

        function analyzeAlertWithAI(alertId) {
            setAiLoadingState(true);
            fetch('../api/ai-alert-analysis.php?alert_id=' + encodeURIComponent(alertId))
                .then(async (r) => {
                    const text = await r.text();
                    let data = null;
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        throw new Error('Server returned invalid JSON (HTTP ' + r.status + '): ' + (text ? text.substring(0, 300) : '[empty response]'));
                    }
                    return data;
                })
                .then(data => {
                    if (!data.success) {
                        throw new Error(data.error || 'AI request failed');
                    }

                    const summary = data.summary || '';
                    const actions = Array.isArray(data.recommended_actions) ? data.recommended_actions : [];

                    const aiDesc = document.getElementById('aiDescription');
                    const aiActions = document.getElementById('aiActions');
                    const aiActionsWrap = document.getElementById('aiActionsWrap');
                    const aiCmdsWrap = document.getElementById('aiCmdsWrap');
                    const aiMeta = document.getElementById('aiMeta');
                    const aiCmds = document.getElementById('aiCommands');

                    if (aiDesc) {
                        aiDesc.innerHTML = escapeHtml(summary || '');
                    }

                    if (aiActionsWrap) aiActionsWrap.style.display = actions.length ? '' : 'none';
                    if (aiActions) {
                        aiActions.innerHTML = actions.map(a => `<li>${escapeHtml(a)}</li>`).join('') || '<li>No actions returned</li>';
                    }

                    const commands = Array.isArray(data.suggested_commands) ? data.suggested_commands : [];
                    const lines = commands
                        .map(c => {
                            if (!c) return '';
                            const label = (c && c.label) ? String(c.label) : '';
                            const cmd = (c && c.command) ? String(c.command) : '';
                            const text = (label && cmd) ? (label + ': ' + cmd) : (cmd || label);
                            return text.trim();
                        })
                        .filter(Boolean);

                    if (aiCmds) {
                        aiCmds.innerHTML = lines.length
                            ? ('<ul>' + lines.map(x => `<li style="font-family:monospace; font-size:12px;">${escapeHtml(x)}</li>`).join('') + '</ul>')
                            : '<div style="color:#666; font-size:12px;">No commands suggested</div>';
                    }

                    if (aiMeta) {
                        aiMeta.innerHTML = `Model: <code>${escapeHtml(data.model || '')}</code> | Provider: <code>${escapeHtml(data.provider || '')}</code> ${data.cached ? '(cached)' : ''}`;
                    }

                    if (!summary && actions.length === 0) {
                        throw new Error('AI returned empty results. Check API key/model or try Re-Analyze.');
                    }

                    const toggle = document.getElementById('toggleOriginal');
                    if (toggle) {
                        toggle.checked = false;
                    }
                    toggleOriginal(false);
                })
                .catch(err => {
                    const aiDesc = document.getElementById('aiDescription');
                    const aiActions = document.getElementById('aiActions');
                    const aiBox = document.getElementById('aiBox');
                    const aiMeta = document.getElementById('aiMeta');
                    const aiCmds = document.getElementById('aiCommands');
                    if (aiBox) aiBox.style.display = '';
                    if (aiDesc) {
                        aiDesc.style.display = '';
                        aiDesc.innerHTML = `<span style="color:#b00020; font-weight:600;">AI Error:</span> ${escapeHtml(err.message)}`;
                    }
                    if (aiActions) {
                        aiActions.style.display = 'none';
                    }
                    if (aiMeta) {
                        aiMeta.innerHTML = '<span style="color:#b00020;">AI analysis failed</span>';
                    }
                    if (aiCmds) {
                        aiCmds.innerHTML = '';
                    }
                })
                .finally(() => {
                    setAiLoadingState(false);
                });
        }

        function loadIncidentStory(force) {
            const box = document.getElementById('incidentBox');
            const titleEl = document.getElementById('incidentTitle');
            const storyEl = document.getElementById('incidentStory');
            const tlEl = document.getElementById('incidentTimeline');
            const stepsEl = document.getElementById('incidentSteps');
            const cmdsEl = document.getElementById('incidentCommands');
            const metaEl = document.getElementById('incidentMeta');

            if (!box) return;

            const host = lastAlertDetails && lastAlertDetails.details && (lastAlertDetails.details.computer || lastAlertDetails.details.host || lastAlertDetails.details.agent)
                ? (lastAlertDetails.details.computer || lastAlertDetails.details.host || lastAlertDetails.details.agent)
                : '';

            box.style.display = '';
            if (!host) {
                if (titleEl) titleEl.textContent = 'Incident Story';
                if (storyEl) storyEl.innerHTML = '<span style="color:#b00020;">No host/computer found for this alert.</span>';
                if (tlEl) tlEl.innerHTML = '';
                if (stepsEl) stepsEl.innerHTML = '';
                if (metaEl) metaEl.textContent = '';
                return;
            }

            if (titleEl) titleEl.textContent = 'Incident Story (' + host + ')';
            if (storyEl) storyEl.textContent = 'Loading...';
            if (tlEl) tlEl.innerHTML = '';
            if (stepsEl) stepsEl.innerHTML = '';
            if (cmdsEl) cmdsEl.innerHTML = '';
            if (metaEl) metaEl.textContent = '';

            const url = BASE_PATH + '/api/ai-incident-story.php?host=' + encodeURIComponent(host) + '&hours=12' + (force ? '&force=1' : '');
            fetch(url)
                .then(async (r) => {
                    const text = await r.text();
                    let data = null;
                    try { data = JSON.parse(text); } catch (e) {
                        throw new Error('Server returned invalid JSON (HTTP ' + r.status + '): ' + (text ? text.substring(0, 300) : '[empty response]'));
                    }
                    return data;
                })
                .then(data => {
                    if (!data.success) throw new Error(data.error || 'Incident story request failed');
                    const payload = data.payload || {};
                    const t = payload.story_title || 'Incident Story';
                    const s = payload.story || '';
                    const timeline = Array.isArray(payload.timeline) ? payload.timeline : [];
                    const steps = Array.isArray(payload.next_steps) ? payload.next_steps : [];
                    const cmds = Array.isArray(payload.suggested_commands) ? payload.suggested_commands : [];

                    if (titleEl) titleEl.textContent = t;
                    if (storyEl) storyEl.textContent = s;
                    if (tlEl) tlEl.innerHTML = timeline.map(x => `<li>${escapeHtml(x)}</li>`).join('') || '<li>No correlated activity found</li>';
                    if (stepsEl) stepsEl.innerHTML = steps.map(x => `<li>${escapeHtml(x)}</li>`).join('') || '<li>No next steps returned</li>';

                    if (cmdsEl) {
                        const agent = host;
                        const list = cmds
                            .map(c => {
                                if (!c) return '';
                                const label = typeof c === 'object' && c.label ? String(c.label) : 'Command';
                                const cmd = typeof c === 'object' && c.command ? String(c.command) : (typeof c === 'string' ? c : '');
                                if (!cmd.trim()) return '';
                                const rtUrl = 'remote-terminal.php?agent=' + encodeURIComponent(agent) + '&cmd=' + encodeURIComponent(cmd);
                                return `
                                    <li style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
                                        <div style="min-width:0;">
                                            <div style="font-weight:600;">${escapeHtml(label)}</div>
                                            <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; font-size:12px; color:#333; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(cmd)}</div>
                                        </div>
                                        <div style="display:flex; gap:6px; flex-shrink:0;">
                                            <button type="button" class="btn-view" style="padding:6px 10px; font-size:12px;" onclick="navigator.clipboard.writeText(${JSON.stringify(cmd)});">Copy</button>
                                            <a class="btn-view" style="padding:6px 10px; font-size:12px; text-decoration:none;" href="${rtUrl}">Run</a>
                                        </div>
                                    </li>
                                `;
                            })
                            .filter(Boolean)
                            .join('');

                        if (list) {
                            cmdsEl.innerHTML = list;
                        } else {
                            cmdsEl.innerHTML = '<li>No commands suggested</li>';
                        }
                    }

                    if (metaEl) {
                        metaEl.innerHTML = `Model: <code>${escapeHtml(data.model || '')}</code> | Provider: <code>${escapeHtml(data.provider || '')}</code> ${data.cached ? '(cached)' : ''}`;
                    }
                })
                .catch(err => {
                    if (storyEl) storyEl.innerHTML = `<span style="color:#b00020; font-weight:600;">Incident Story Error:</span> ${escapeHtml(err.message)}`;
                    if (tlEl) tlEl.innerHTML = '';
                    if (stepsEl) stepsEl.innerHTML = '';
                    if (cmdsEl) cmdsEl.innerHTML = '';
                    if (metaEl) metaEl.innerHTML = '<span style="color:#b00020;">Incident story failed</span>';
                });
        }

        function viewAlert(alertId) {
            fetch(BASE_PATH + '/api/threat-detection.php?action=get_alert&alert_id=' + encodeURIComponent(alertId))
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
                                <span class="severity-badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span>
                            </div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Status:</div>
                            <div class="detail-value">
                                <span class="status-badge status-${alert.status}">${alert.status.charAt(0).toUpperCase() + alert.status.slice(1)}</span>
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
                            <div class="detail-value" id="origDescription">${escapeHtml(alert.description)}</div>
                            <div class="detail-value" id="legacyAiDescription" style="display:none;"></div>
                        </div>

                        <div class="recommendations">
                            <h4>Recommended Actions:</h4>
                            <ul id="origActions">
                                ${(alert.recommended_actions || []).map(action => `<li>${escapeHtml(action)}</li>`).join('')}
                            </ul>
                            <ul id="legacyAiActions" style="display:none;"></ul>
                        </div>

                        <div id="aiBox" class="ai-card" style="display:none;">
                            <div class="ai-card-header">
                                <div class="ai-card-title"><i class="fas fa-robot"></i> AI Alert Analysis</div>
                                <span class="ai-badge">AI</span>
                            </div>
                            <div id="aiMeta" class="ai-meta"></div>
                            <div class="ai-section">
                                <div class="ai-section-title"><i class="fas fa-align-left"></i> Summary</div>
                                <div id="aiDescription" class="ai-text"></div>
                            </div>
                            <div class="ai-section" id="aiActionsWrap" style="display:none;">
                                <div class="ai-section-title"><i class="fas fa-list-check"></i> Recommended Actions</div>
                                <ul id="aiActions" class="ai-list"></ul>
                            </div>
                            <div class="ai-section" id="aiCmdsWrap" style="display:none;">
                                <div class="ai-section-title"><i class="fas fa-terminal"></i> Suggested Commands</div>
                                <div id="aiCommands"></div>
                            </div>
                        </div>

                        <div id="incidentBox" class="ai-card" style="display:none;">
                            <div class="ai-card-header">
                                <div id="incidentTitle" class="ai-card-title"><i class="fas fa-link"></i> Incident Story</div>
                                <button type="button" class="btn-ai-link" onclick="loadIncidentStory(true);">Refresh</button>
                            </div>
                            <div id="incidentMeta" class="ai-meta"></div>
                            <div class="ai-section">
                                <div class="ai-section-title"><i class="fas fa-book"></i> Story</div>
                                <div id="incidentStory" class="ai-text"></div>
                            </div>
                            <div class="ai-section">
                                <div class="ai-section-title"><i class="fas fa-clock"></i> Timeline</div>
                                <ul id="incidentTimeline" class="ai-list"></ul>
                            </div>
                            <div class="ai-section">
                                <div class="ai-section-title"><i class="fas fa-route"></i> Next Steps</div>
                                <ul id="incidentSteps" class="ai-list"></ul>
                            </div>
                            <div class="ai-section">
                                <div class="ai-section-title"><i class="fas fa-terminal"></i> Suggested Commands</div>
                                <ul id="incidentCommands" class="ai-cmd-list"></ul>
                            </div>
                        </div>

                        <div style="margin-top: 15px; display: flex; gap: 10px; align-items: center;">
                            <label style="font-size: 12px; color: #666; display: flex; gap: 6px; align-items: center; white-space: nowrap;">
                                <input type="checkbox" id="toggleOriginal" onchange="toggleOriginal(this.checked)">
                                Show Original
                            </label>
                        </div>

                        <form method="POST" style="margin-top: 20px;">
                            <input type="hidden" name="alert_id" value="${escapeHtml(alert.alert_id)}">
                            <input type="hidden" name="action" value="update">

                            <div style="margin-bottom: 15px;">
                                <label style="display:block; font-weight: 600; color:#666; font-size: 13px; margin-bottom: 5px;">Update Status:</label>
                                <select name="status" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 13px;">
                                    <option value="new" ${alert.status === 'new' ? 'selected' : ''}>New</option>
                                    <option value="acknowledged" ${alert.status === 'acknowledged' ? 'selected' : ''}>Acknowledged</option>
                                    <option value="resolved" ${alert.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                                </select>
                            </div>

                            <div style="margin-bottom: 15px;">
                                <label style="display:block; font-weight: 600; color:#666; font-size: 13px; margin-bottom: 5px;">Notes:</label>
                                <textarea name="notes" placeholder="Add investigation notes..." style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 13px; font-family: inherit; min-height: 80px;">${escapeHtml(alert.notes || '')}</textarea>
                            </div>

                            <button type="submit" class="btn-view" style="width: 100%;">
                                <i class="fas fa-save"></i> Update Alert
                            </button>
                        </form>
                    `;

                    document.getElementById('alertDetails').innerHTML = html;
                    document.getElementById('alertModal').classList.add('active');

                    // Default behavior: show AI analysis results (original hidden unless toggled)
                    const toggle = document.getElementById('toggleOriginal');
                    if (toggle) {
                        toggle.checked = false;
                    }
                    toggleOriginal(false);
                    analyzeAlertWithAI(alert.alert_id);
                    lastAlertDetails = alert;
                    loadIncidentStory(false);
                })
                .catch(e => {
                    document.getElementById('alertDetails').innerHTML = '<p style="color: red;">Error loading alert details. Please try again.</p>';
                    document.getElementById('alertModal').classList.add('active');
                });
        }

        function closeModal() {
            document.getElementById('alertModal').classList.remove('active');
        }

        document.addEventListener('DOMContentLoaded', function() {
            const modal = document.getElementById('alertModal');
            if (modal) {
                modal.addEventListener('click', function(e) {
                    if (e.target === this) {
                        closeModal();
                    }
                });
            }

            setInterval(() => {
                const m = document.getElementById('alertModal');
                if (m && m.classList.contains('active')) {
                    return;
                }
                window.location.reload();
            }, 10000);
        });
    </script>
</body>
</html>
