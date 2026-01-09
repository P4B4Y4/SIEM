<?php
/**
 * Event Details Page
 * Display detailed information about a specific event
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

// Get event ID
$event_id = (int)($_GET['id'] ?? 0);

if (!$event_id) {
    header('Location: events.php');
    exit;
}

// Get event details
$result = $db->query("SELECT * FROM security_events WHERE event_id = $event_id");
$event = $result ? $result->fetch_assoc() : null;

if (!$event) {
    header('Location: events.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Event Details - <?php echo APP_NAME; ?></title>
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

        .navbar-menu a:hover {
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
            max-width: 1000px;
            margin: 0 auto;
            padding: 30px;
        }

        .page-header {
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .page-header h1 {
            font-size: 28px;
        }

        .btn-back {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            font-size: 13px;
        }

        .btn-back:hover {
            background: #5568d3;
        }

        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 25px;
            margin-bottom: 20px;
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
        }

        .severity-badge {
            display: inline-block;
            padding: 6px 14px;
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

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }

        .detail-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }

        .ai-card { border: 1px dashed #ddd; border-radius: 10px; background: #fafafa; padding: 12px; }
        .ai-card-header { display:flex; align-items:center; justify-content:space-between; gap:10px; }
        .ai-card-title { font-weight: 800; font-size: 13px; color:#111; display:flex; align-items:center; gap:8px; }
        .ai-badge { display:inline-flex; align-items:center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; border: 1px solid #e5e7eb; background:#fff; color:#4b5563; }
        .ai-meta { font-size: 12px; color: #6b7280; margin-top: 8px; }
        .ai-section { margin-top: 10px; }
        .ai-section-title { font-size: 12px; color: #6b7280; font-weight: 800; text-transform: uppercase; margin-bottom: 6px; display:flex; align-items:center; gap:8px; }
        .ai-text { font-size: 14px; color:#111; line-height: 1.45; white-space: pre-wrap; }
        .ai-list { margin-left: 18px; }
        .ai-list li { margin-bottom: 8px; color:#374151; font-size: 13px; }

        .detail-label {
            font-size: 12px;
            color: #999;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 5px;
        }

        .detail-value {
            font-size: 14px;
            color: #333;
            word-break: break-all;
            font-family: monospace;
        }

        .raw-log {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
        }

        .ai-box {
            background: #fafafa;
            border: 1px dashed #ddd;
            border-radius: 8px;
            padding: 15px;
        }

        .ai-meta {
            font-size: 12px;
            color: #666;
            margin-bottom: 10px;
        }

        .ai-error {
            color: #b00020;
            font-weight: 600;
        }

        @media (max-width: 768px) {
            .detail-grid {
                grid-template-columns: 1fr;
            }

            .page-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
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
            <a href="events.php"><i class="fas fa-list"></i> Events</a>
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
                <h1>Event Details</h1>
                <p style="color: #999; font-size: 14px;">Event ID: <?php echo $event['event_id']; ?></p>
            </div>
            <div style="display:flex; gap: 10px; align-items:center;">
                <?php if (!empty($event['source_ip'])): ?>
                    <a href="task-manager.php?agent=<?php echo urlencode($event['source_ip']); ?>" class="btn-back" style="background:#0066cc;">
                        <i class="fas fa-tasks"></i> Task Manager
                    </a>
                <?php endif; ?>
                <a href="events.php" class="btn-back">
                    <i class="fas fa-arrow-left"></i> Back to Events
                </a>
            </div>
        </div>

        <!-- Event Summary -->
        <div class="card">
            <div class="card-header">
                <div class="card-title"><?php echo escape($event['event_type'] ?? 'Unknown'); ?></div>
                <span class="severity-badge severity-<?php echo strtolower($event['severity'] ?? 'info'); ?>">
                    <?php echo ucfirst($event['severity'] ?? 'Info'); ?>
                </span>
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Timestamp</div>
                    <div class="detail-value"><?php echo date('M d, Y H:i:s', strtotime($event['timestamp'])); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Event Type</div>
                    <div class="detail-value"><?php echo escape($event['event_type'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Severity</div>
                    <div class="detail-value"><?php echo ucfirst($event['severity'] ?? 'Unknown'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Agent ID</div>
                    <div class="detail-value"><?php echo $event['agent_id'] ?? '-'; ?></div>
                </div>
            </div>
        </div>

        <!-- AI Analysis -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">AI Analysis</div>
            </div>
            <div class="ai-card">
                <div class="ai-card-header">
                    <div class="ai-card-title"><i class="fas fa-robot"></i> AI Event Analysis</div>
                    <span class="ai-badge">AI</span>
                </div>
                <div id="aiMeta" class="ai-meta">Analyzing...</div>

                <div class="ai-section">
                    <div class="ai-section-title"><i class="fas fa-align-left"></i> Summary</div>
                    <div id="aiSummary" class="ai-text"></div>
                </div>

                <div class="ai-section">
                    <div class="ai-section-title"><i class="fas fa-list-check"></i> Recommended Actions</div>
                    <ul id="aiActions" class="ai-list"></ul>
                </div>
            </div>
        </div>

        <!-- Network Information -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Network Information</div>
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Source IP</div>
                    <div class="detail-value"><?php echo escape($event['source_ip'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Source Port</div>
                    <div class="detail-value"><?php echo $event['source_port'] ?? '-'; ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Destination IP</div>
                    <div class="detail-value"><?php echo escape($event['dest_ip'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Destination Port</div>
                    <div class="detail-value"><?php echo $event['dest_port'] ?? '-'; ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Protocol</div>
                    <div class="detail-value"><?php echo escape($event['protocol'] ?? '-'); ?></div>
                </div>
            </div>
        </div>

        <!-- Process Information -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Process Information</div>
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">User Account</div>
                    <div class="detail-value"><?php echo escape($event['user_account'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Process Name</div>
                    <div class="detail-value"><?php echo escape($event['process_name'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">File Path</div>
                    <div class="detail-value"><?php echo escape($event['file_path'] ?? '-'); ?></div>
                </div>
            </div>
        </div>

        <!-- Hash Information -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Hash Information</div>
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">MD5</div>
                    <div class="detail-value"><?php echo escape($event['hash_md5'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">SHA256</div>
                    <div class="detail-value"><?php echo escape($event['hash_sha256'] ?? '-'); ?></div>
                </div>
            </div>
        </div>

        <!-- Threat Intelligence -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Threat Intelligence</div>
            </div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">MITRE Tactic</div>
                    <div class="detail-value"><?php echo escape($event['mitre_tactic'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">MITRE Technique</div>
                    <div class="detail-value"><?php echo escape($event['mitre_technique'] ?? '-'); ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Threat Intel Match</div>
                    <div class="detail-value"><?php echo $event['threat_intel_match'] ? 'Yes' : 'No'; ?></div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">UEBA Risk Score</div>
                    <div class="detail-value"><?php echo $event['ueba_risk_score'] ?? '-'; ?></div>
                </div>
            </div>
        </div>

        <!-- Raw Event Data -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Raw Event Data</div>
            </div>
            <div class="raw-log"><?php echo escape($event['event_data'] ?? 'No data available'); ?></div>
        </div>

        <!-- Raw Log -->
        <?php if ($event['raw_log']): ?>
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Raw Log</div>
                </div>
                <div class="raw-log"><?php echo escape($event['raw_log']); ?></div>
            </div>
        <?php endif; ?>
    </div>
    
    <?php
    // Handle logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit;
    }
    ?>

    <script>
        function escapeHtml(str) {
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        (function runAiEventAnalysis() {
            const eventId = <?php echo (int)$event['event_id']; ?>;
            fetch('../api/ai-event-analysis.php?event_id=' + encodeURIComponent(eventId))
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        throw new Error(data.error || 'AI request failed');
                    }

                    const summary = data.summary || '';
                    const actions = Array.isArray(data.recommended_actions) ? data.recommended_actions : [];

                    const meta = document.getElementById('aiMeta');
                    const sumEl = document.getElementById('aiSummary');
                    const actEl = document.getElementById('aiActions');

                    if (meta) {
                        meta.innerHTML = `Model: <code>${escapeHtml(data.model || '')}</code> | Provider: <code>${escapeHtml(data.provider || '')}</code> ${data.cached ? '(cached)' : ''}`;
                    }
                    if (sumEl) {
                        sumEl.textContent = summary;
                    }
                    if (actEl) {
                        actEl.innerHTML = actions.map(a => `<li>${escapeHtml(a)}</li>`).join('') || '<li>No actions returned</li>';
                    }
                })
                .catch(err => {
                    const meta = document.getElementById('aiMeta');
                    const sumEl = document.getElementById('aiSummary');
                    const actEl = document.getElementById('aiActions');
                    if (meta) {
                        meta.innerHTML = `<span class="ai-error">AI Error:</span> ${escapeHtml(err.message)}`;
                    }
                    if (sumEl) sumEl.textContent = '';
                    if (actEl) actEl.innerHTML = '';
                });
        })();
    </script>
</body>
</html>
