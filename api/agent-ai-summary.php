<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
header('Content-Type: application/json');

if (!isset($_SESSION['user_id']) && !isset($_SESSION['username'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/../config/config.php';

$hours = isset($_GET['hours']) ? max(1, min(72, (int)$_GET['hours'])) : 24;
$status_threshold_minutes = isset($_GET['status_mins']) ? max(1, min(240, (int)$_GET['status_mins'])) : 15;
$refresh_status = isset($_GET['refresh_status']) && $_GET['refresh_status'] === '1';

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Database connection failed']);
    exit;
}

// Cache table for command-based online/offline status
$db->query("CREATE TABLE IF NOT EXISTS agent_status_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent VARCHAR(128) NOT NULL,
    last_ping_command_id INT NULL,
    last_ping_sent_at DATETIME NULL,
    last_ping_completed_at DATETIME NULL,
    last_ping_status VARCHAR(32) NULL,
    last_ping_output VARCHAR(255) NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_agent (agent)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// Identify agents from events
$agents = [];

// Some deployments use different columns to represent the agent/host.
// Prefer agent_id, but fall back to source_ip or user_account if needed.
$agentQuery = "
    SELECT agent AS agent, MAX(timestamp) AS last_seen, COUNT(*) AS total_events
    FROM (
        SELECT agent_id AS agent, timestamp FROM security_events WHERE agent_id IS NOT NULL AND agent_id <> ''
        UNION ALL
        SELECT source_ip AS agent, timestamp FROM security_events WHERE (agent_id IS NULL OR agent_id = '') AND source_ip IS NOT NULL AND source_ip <> ''
        UNION ALL
        SELECT user_account AS agent, timestamp FROM security_events WHERE (agent_id IS NULL OR agent_id = '') AND (source_ip IS NULL OR source_ip = '') AND user_account IS NOT NULL AND user_account <> ''
    ) t
    GROUP BY agent
    ORDER BY last_seen DESC
    LIMIT 15
";

$agentRes = $db->query($agentQuery);
if ($agentRes) {
    while ($row = $agentRes->fetch_assoc()) {
        $agents[] = [
            'agent' => (string)($row['agent'] ?? ''),
            'last_seen' => (string)($row['last_seen'] ?? ''),
            'total_events' => (int)($row['total_events'] ?? 0)
        ];
    }
}

$sevRank = function (string $sev): int {
    $s = strtolower($sev);
    if ($s === 'critical') return 4;
    if ($s === 'high') return 3;
    if ($s === 'medium') return 2;
    return 1;
};

$outAgents = [];
foreach ($agents as $a) {
    $agent = $a['agent'];
    $lastSeen = $a['last_seen'];
    $status = 'unknown';
    if ($lastSeen) {
        $t = strtotime($lastSeen);
        if ($t) {
            $status = (time() - $t) <= ($status_threshold_minutes * 60) ? 'online' : 'offline';
        }
    }

    // If we have a recent command completion, prefer it for online/offline
    $cmd_status = null;
    $cmd_completed_at = null;
    $cmd_sent_at = null;
    $cmd_id = null;
    $cache_stmt = $db->prepare('SELECT last_ping_command_id, last_ping_sent_at, last_ping_completed_at, last_ping_status, last_ping_output, updated_at FROM agent_status_cache WHERE agent=? LIMIT 1');
    if ($cache_stmt) {
        $cache_stmt->bind_param('s', $agent);
        $cache_stmt->execute();
        $cache_res = $cache_stmt->get_result();
        if ($cache_res && $cache_res->num_rows > 0) {
            $row = $cache_res->fetch_assoc();
            $cmd_id = isset($row['last_ping_command_id']) ? (int)$row['last_ping_command_id'] : null;
            $cmd_status = $row['last_ping_status'] ?? null;
            $cmd_completed_at = $row['last_ping_completed_at'] ?? null;
            $cmd_sent_at = $row['last_ping_sent_at'] ?? null;
        }
        $cache_stmt->close();
    }

    // If we have a ping command id, try to refresh its completion from remote_commands
    if ($cmd_id) {
        $rs = $db->prepare('SELECT status, output, error, completed_at FROM remote_commands WHERE id=? LIMIT 1');
        if ($rs) {
            $rs->bind_param('i', $cmd_id);
            $rs->execute();
            $rr = $rs->get_result();
            if ($rr && $rr->num_rows > 0) {
                $rrow = $rr->fetch_assoc();
                $st = (string)($rrow['status'] ?? '');
                $ca = (string)($rrow['completed_at'] ?? '');
                $out = (string)($rrow['output'] ?? '');
                $err = (string)($rrow['error'] ?? '');
                if ($ca !== '') {
                    $cmd_completed_at = $ca;
                    $cmd_status = $st !== '' ? $st : $cmd_status;
                    $cmd_output = trim($out !== '' ? $out : $err);
                    if (strlen($cmd_output) > 255) $cmd_output = substr($cmd_output, 0, 255);

                    $upc = $db->prepare('INSERT INTO agent_status_cache (agent, last_ping_command_id, last_ping_sent_at, last_ping_completed_at, last_ping_status, last_ping_output) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE last_ping_completed_at=VALUES(last_ping_completed_at), last_ping_status=VALUES(last_ping_status), last_ping_output=VALUES(last_ping_output)');
                    if ($upc) {
                        $sent_at = $cmd_sent_at ? $cmd_sent_at : date('Y-m-d H:i:s');
                        $upc->bind_param('sissss', $agent, $cmd_id, $sent_at, $cmd_completed_at, $cmd_status, $cmd_output);
                        $upc->execute();
                        $upc->close();
                    }
                }
            }
            $rs->close();
        }
    }

    // Status mode B: command-based. Online if last ping completed within threshold.
    if ($cmd_completed_at) {
        $ct = strtotime((string)$cmd_completed_at);
        if ($ct) {
            $status = (time() - $ct) <= ($status_threshold_minutes * 60) ? 'online' : 'offline';
        }
    }

    // Count anomaly-like events per type in window
    $anomalyCounts = [
        'disk' => 0,
        'memory' => 0,
        'cpu' => 0,
        'crash' => 0
    ];
    $maxSev = 'low';
    $eventCountWindow = 0;

    $stmt = $db->prepare("SELECT event_type, severity, timestamp
                          FROM security_events
                          WHERE (agent_id = ? OR source_ip = ? OR user_account = ?)
                          AND timestamp >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                          ORDER BY timestamp DESC
                          LIMIT 400");
    $stmt->bind_param('sssi', $agent, $agent, $agent, $hours);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $eventCountWindow++;
        $etype = strtolower((string)($row['event_type'] ?? ''));
        $sev = strtolower((string)($row['severity'] ?? 'low'));
        if ($sevRank($sev) > $sevRank($maxSev)) $maxSev = $sev;

        if (strpos($etype, 'disk') !== false || strpos($etype, 'disk_anomaly') !== false) $anomalyCounts['disk']++;
        if (strpos($etype, 'memory') !== false || strpos($etype, 'memory_anomaly') !== false) $anomalyCounts['memory']++;
        if (strpos($etype, 'cpu') !== false || strpos($etype, 'cpu_anomaly') !== false) $anomalyCounts['cpu']++;

        if (strpos($etype, 'crash') !== false || strpos($etype, 'service stopped') !== false || strpos($etype, 'unexpected shutdown') !== false) {
            $anomalyCounts['crash']++;
        }
    }
    $stmt->close();

    $issues = [];
    if ($anomalyCounts['disk'] > 0) $issues[] = 'Disk anomalies (' . $anomalyCounts['disk'] . ')';
    if ($anomalyCounts['memory'] > 0) $issues[] = 'Memory anomalies (' . $anomalyCounts['memory'] . ')';
    if ($anomalyCounts['cpu'] > 0) $issues[] = 'CPU anomalies (' . $anomalyCounts['cpu'] . ')';
    if ($anomalyCounts['crash'] >= 3) $issues[] = 'Crash indicators (' . $anomalyCounts['crash'] . ')';

    // Missing logs pattern in the analysis window (does not define online/offline)
    if ($eventCountWindow === 0) {
        $issues[] = 'Missing logs in last ' . $hours . 'h (agent not reporting)';
    } elseif ($eventCountWindow < 5) {
        $issues[] = 'Low log volume in last ' . $hours . 'h (' . $eventCountWindow . ' events)';
    }

    if ($status === 'offline') {
        $issues[] = 'Agent appears offline (no successful ping response within ~' . $status_threshold_minutes . 'm)';
    }

    $suggested = [];
    if ($anomalyCounts['disk'] > 0) {
        $suggested[] = 'Check disk health (SMART), free space, and System event logs for disk errors.';
        $suggested[] = 'Validate if disk spikes correlate with updates, backup jobs, or suspicious encryption activity.';
    }
    if ($anomalyCounts['memory'] > 0) {
        $suggested[] = 'Check top memory consumers and recent process restarts; look for memory leaks.';
    }
    if ($anomalyCounts['cpu'] > 0) {
        $suggested[] = 'Check top CPU processes and scheduled tasks; verify no crypto-mining behavior.';
    }
    if ($anomalyCounts['crash'] >= 3) {
        $suggested[] = 'Review Windows Reliability Monitor / Application logs for repeated crashes.';
        $suggested[] = 'If a service is crashing, check service recovery settings and recent config changes.';
    }
    if ($eventCountWindow === 0 || $status === 'offline') {
        $suggested[] = 'Confirm agent service is running and network connectivity to collector is stable.';
        $suggested[] = 'Check firewall/proxy rules that might block log shipping.';
    }

    // Keep output small (dashboard is a quick glance)
    if (count($issues) > 4) $issues = array_slice($issues, 0, 4);
    if (count($suggested) > 2) $suggested = array_slice($suggested, 0, 2);

    $outAgents[] = [
        'agent' => $agent,
        'status' => $status,
        'last_seen' => $lastSeen,
        'window_hours' => $hours,
        'status_threshold_minutes' => $status_threshold_minutes,
        'status_mode' => 'command',
        'last_ping_sent_at' => $cmd_sent_at,
        'last_ping_completed_at' => $cmd_completed_at,
        'last_ping_status' => $cmd_status,
        'max_severity' => $maxSev,
        'event_count_window' => $eventCountWindow,
        'issues' => $issues,
        'suggested_checks' => $suggested
    ];
}

// Fan-out ping if requested (rate-limited by 30s TTL)
if ($refresh_status && count($agents) > 0) {
    // Only enqueue if we haven't sent one recently
    $pingCmd = 'cmd /c echo SIEM_PING_%COMPUTERNAME%_%DATE%_%TIME%';
    foreach ($agents as $a) {
        $agent = $a['agent'];
        $shouldSend = true;
        $row = null;
        $st = $db->prepare('SELECT last_ping_sent_at FROM agent_status_cache WHERE agent=? LIMIT 1');
        if ($st) {
            $st->bind_param('s', $agent);
            $st->execute();
            $rs = $st->get_result();
            if ($rs && $rs->num_rows > 0) {
                $row = $rs->fetch_assoc();
            }
            $st->close();
        }
        if ($row && !empty($row['last_ping_sent_at'])) {
            $sentTs = strtotime((string)$row['last_ping_sent_at']);
            if ($sentTs && (time() - $sentTs) < 30) {
                $shouldSend = false;
            }
        }
        if (!$shouldSend) {
            continue;
        }

        // Insert into remote_commands directly (same pipeline as remote-access.php?action=send_command)
        $ins = $db->prepare("INSERT INTO remote_commands (agent_name, command, timestamp, status) VALUES (?, ?, NOW(), 'pending')");
        if ($ins) {
            $ins->bind_param('ss', $agent, $pingCmd);
            if ($ins->execute()) {
                $cmdId = (int)$db->insert_id;
                $up = $db->prepare('INSERT INTO agent_status_cache (agent, last_ping_command_id, last_ping_sent_at, last_ping_status) VALUES (?, ?, NOW(), ?) ON DUPLICATE KEY UPDATE last_ping_command_id=VALUES(last_ping_command_id), last_ping_sent_at=VALUES(last_ping_sent_at), last_ping_status=VALUES(last_ping_status)');
                if ($up) {
                    $pending = 'pending';
                    $up->bind_param('sis', $agent, $cmdId, $pending);
                    $up->execute();
                    $up->close();
                }
            }
            $ins->close();
        }
    }
}

echo json_encode([
    'success' => true,
    'hours' => $hours,
    'status_threshold_minutes' => $status_threshold_minutes,
    'refresh_status' => $refresh_status,
    'agents' => $outAgents
]);

$db->close();
