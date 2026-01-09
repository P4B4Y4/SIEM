<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
header('Content-Type: application/json');

// Ensure JSON output even on fatal errors
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: application/json');
        }
        echo json_encode([
            'success' => false,
            'error' => 'Server error',
            'details' => ($err['message'] ?? 'Fatal error') . ' in ' . ($err['file'] ?? '') . ':' . ($err['line'] ?? 0)
        ]);
    }
});

if (!isset($_SESSION['user_id']) && !isset($_SESSION['username'])) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error' => 'Unauthorized',
        'details' => 'Not logged in or session cookie not sent'
    ]);
    exit;
}

require_once __DIR__ . '/../config/config.php';

// Load settings from config/settings.json (same source used elsewhere)
$settings_path = __DIR__ . '/../config/settings.json';
$settings = [];
if (is_file($settings_path)) {
    $raw = file_get_contents($settings_path);
    $decoded = json_decode((string)$raw, true);
    if (is_array($decoded)) {
        $settings = $decoded;
    }
}

$getSetting = function (string $key, $default = null) use (&$settings) {
    $parts = explode('.', $key);
    $cur = $settings;
    foreach ($parts as $p) {
        if (!is_array($cur) || !array_key_exists($p, $cur)) {
            return $default;
        }
        $cur = $cur[$p];
    }
    return $cur;
};

$ai_enabled = (bool)$getSetting('ai.enabled', false);
$ai_provider = (string)$getSetting('ai.provider', 'groq');
$ai_model = (string)$getSetting('ai.model', 'openai/gpt-oss-20b');
$ai_api_key = (string)$getSetting('ai.api_key', '');

$force = isset($_GET['force']) && $_GET['force'] === '1';

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Database connection failed']);
    exit;
}

// Cache table
$db->query("CREATE TABLE IF NOT EXISTS dashboard_ai_summary (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cache_key VARCHAR(64) NOT NULL,
    model VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    summary TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cache_model_provider (cache_key, model, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$cache_key = 'last24h';

if (!$force) {
    $c = $db->prepare('SELECT summary, updated_at FROM dashboard_ai_summary WHERE cache_key=? AND model=? AND provider=? LIMIT 1');
    $c->bind_param('sss', $cache_key, $ai_model, $ai_provider);
    $c->execute();
    $res = $c->get_result();
    if ($res && $res->num_rows > 0) {
        $row = $res->fetch_assoc();
        $c->close();

        // TTL = 15 minutes
        $updated = strtotime((string)$row['updated_at']);
        if ($updated && (time() - $updated) < (15 * 60)) {
            echo json_encode([
                'success' => true,
                'cached' => true,
                'model' => $ai_model,
                'provider' => $ai_provider,
                'summary' => (string)($row['summary'] ?? ''),
                'updated_at' => $row['updated_at']
            ]);
            $db->close();
            exit;
        }
    } else {
        $c->close();
    }
}

// Collect stats from last 24h
$stats = [
    'events_total' => 0,
    'events_by_severity' => [],
    'top_event_types' => [],
    'top_sources' => [],
    'alerts_total' => 0,
    'alerts_by_severity' => [],
    'top_alert_categories' => []
];

// Events totals
$r = $db->query("SELECT COUNT(*) as c FROM security_events WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
$stats['events_total'] = $r ? (int)($r->fetch_assoc()['c'] ?? 0) : 0;

// Events by severity
$r = $db->query("SELECT LOWER(severity) as sev, COUNT(*) as c FROM security_events WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY LOWER(severity) ORDER BY c DESC");
if ($r) {
    while ($row = $r->fetch_assoc()) {
        $sev = (string)($row['sev'] ?? 'unknown');
        $stats['events_by_severity'][$sev] = (int)($row['c'] ?? 0);
    }
}

// Top event types
$r = $db->query("SELECT event_type, COUNT(*) as c FROM security_events WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY event_type ORDER BY c DESC LIMIT 6");
if ($r) {
    while ($row = $r->fetch_assoc()) {
        $stats['top_event_types'][] = ['event_type' => (string)($row['event_type'] ?? 'Unknown'), 'count' => (int)($row['c'] ?? 0)];
    }
}

// Top sources
$r = $db->query("SELECT source_ip, COUNT(*) as c FROM security_events WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY source_ip ORDER BY c DESC LIMIT 6");
if ($r) {
    while ($row = $r->fetch_assoc()) {
        $stats['top_sources'][] = ['source_ip' => (string)($row['source_ip'] ?? 'Unknown'), 'count' => (int)($row['c'] ?? 0)];
    }
}

// Alerts (if table exists)
$tables = $db->query("SHOW TABLES LIKE 'security_alerts'");
if ($tables && $tables->num_rows > 0) {
    $r = $db->query("SELECT COUNT(*) as c FROM security_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    $stats['alerts_total'] = $r ? (int)($r->fetch_assoc()['c'] ?? 0) : 0;

    $r = $db->query("SELECT LOWER(severity) as sev, COUNT(*) as c FROM security_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY LOWER(severity) ORDER BY c DESC");
    if ($r) {
        while ($row = $r->fetch_assoc()) {
            $sev = (string)($row['sev'] ?? 'unknown');
            $stats['alerts_by_severity'][$sev] = (int)($row['c'] ?? 0);
        }
    }

    $r = $db->query("SELECT category, COUNT(*) as c FROM security_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY category ORDER BY c DESC LIMIT 6");
    if ($r) {
        while ($row = $r->fetch_assoc()) {
            $stats['top_alert_categories'][] = ['category' => (string)($row['category'] ?? 'Unknown'), 'count' => (int)($row['c'] ?? 0)];
        }
    }
}

// --- Deterministic template summary (no AI) ---
$toInt = function ($v): int {
    return is_numeric($v) ? (int)$v : 0;
};

$eventsTotal = $toInt($stats['events_total'] ?? 0);
$alertsTotal = $toInt($stats['alerts_total'] ?? 0);

$sevOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
$pickSev = function (array $counts) use ($sevOrder): array {
    $out = [];
    foreach ($sevOrder as $s) {
        if (isset($counts[$s]) && (int)$counts[$s] > 0) {
            $out[] = $s . ':' . (int)$counts[$s];
        }
    }
    // include any other severities at the end
    foreach ($counts as $k => $v) {
        if (in_array((string)$k, $sevOrder, true)) continue;
        if ((int)$v > 0) $out[] = (string)$k . ':' . (int)$v;
    }
    return $out;
};

$topTypes = array_map(
    fn($x) => (string)($x['event_type'] ?? 'Unknown') . ' (' . (int)($x['count'] ?? 0) . ')',
    is_array($stats['top_event_types'] ?? null) ? $stats['top_event_types'] : []
);
$topSrc = array_map(
    fn($x) => (string)($x['source_ip'] ?? 'Unknown') . ' (' . (int)($x['count'] ?? 0) . ')',
    is_array($stats['top_sources'] ?? null) ? $stats['top_sources'] : []
);
$topCats = array_map(
    fn($x) => (string)($x['category'] ?? 'Unknown') . ' (' . (int)($x['count'] ?? 0) . ')',
    is_array($stats['top_alert_categories'] ?? null) ? $stats['top_alert_categories'] : []
);

$eventSevPairs = $pickSev(is_array($stats['events_by_severity'] ?? null) ? $stats['events_by_severity'] : []);
$alertSevPairs = $pickSev(is_array($stats['alerts_by_severity'] ?? null) ? $stats['alerts_by_severity'] : []);

$headline = 'Last 24h: ' . $eventsTotal . ' events, ' . $alertsTotal . ' alerts.';

$highlights = [];
if (count($eventSevPairs) > 0) {
    $highlights[] = 'Event severities: ' . implode(', ', array_slice($eventSevPairs, 0, 6));
}
if (count($alertSevPairs) > 0) {
    $highlights[] = 'Alert severities: ' . implode(', ', array_slice($alertSevPairs, 0, 6));
}
if (count($topTypes) > 0) {
    $highlights[] = 'Top event types: ' . implode(', ', array_slice($topTypes, 0, 3));
}
if (count($topSrc) > 0) {
    $highlights[] = 'Top sources: ' . implode(', ', array_slice($topSrc, 0, 3));
}
if (count($topCats) > 0) {
    $highlights[] = 'Top alert categories: ' . implode(', ', array_slice($topCats, 0, 3));
}
if (count($highlights) > 5) {
    $highlights = array_slice($highlights, 0, 5);
}

$critA = (int)($stats['alerts_by_severity']['critical'] ?? 0);
$highA = (int)($stats['alerts_by_severity']['high'] ?? 0);
$critE = (int)($stats['events_by_severity']['critical'] ?? 0);
$highE = (int)($stats['events_by_severity']['high'] ?? 0);

$focus = [];
if (($critA + $highA + $critE + $highE) > 0) {
    $focus[] = 'Prioritize critical/high triage and validate affected hosts.';
}
if (count($topSrc) > 0) {
    $focus[] = 'Investigate noisy sources and confirm whether they are expected.';
}
if (count($topTypes) > 0) {
    $focus[] = 'Review the top event types for repeated failures or suspicious execution.';
}
if ($alertsTotal === 0 && $eventsTotal > 0) {
    $focus[] = 'No alerts generated: confirm detection rules and alert pipeline are active.';
}
if (count($focus) < 3) {
    $focus[] = 'Confirm collector/agent coverage and check for telemetry gaps.';
}
if (count($focus) > 5) {
    $focus = array_slice($focus, 0, 5);
}

$top_sources = array_slice($topSrc, 0, 5);
$top_event_types = array_slice($topTypes, 0, 5);

$cleanList = function ($arr, $max) {
    if (!is_array($arr)) return [];
    $out = [];
    foreach ($arr as $x) {
        if (!is_string($x)) continue;
        $t = trim(preg_replace('/\s+/', ' ', strip_tags($x)));
        if ($t !== '') $out[] = $t;
        if (count($out) >= $max) break;
    }
    return $out;
};

$headline = trim(preg_replace('/\s+/', ' ', strip_tags($headline)));
$highlights = $cleanList($highlights, 5);
$top_sources = $cleanList($top_sources, 5);
$top_event_types = $cleanList($top_event_types, 5);
$focus = $cleanList($focus, 5);

if ($headline === '' && count($highlights) === 0) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'AI returned empty response']);
    $db->close();
    exit;
}

$summary_payload = json_encode([
    'headline' => $headline,
    'highlights' => $highlights,
    'top_sources' => $top_sources,
    'top_event_types' => $top_event_types,
    'focus' => $focus
], JSON_UNESCAPED_SLASHES);
if ($summary_payload === false) {
    $summary_payload = json_encode(['headline' => $headline]);
}

// Cache it
$ins = $db->prepare('INSERT INTO dashboard_ai_summary (cache_key, model, provider, summary) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE summary=VALUES(summary)');
$ins->bind_param('ssss', $cache_key, $ai_model, $ai_provider, $summary_payload);
$ins->execute();
$ins->close();

echo json_encode([
    'success' => true,
    'cached' => false,
    'model' => $ai_model,
    'provider' => $ai_provider,
    'summary' => json_decode($summary_payload, true)
]);

$db->close();
