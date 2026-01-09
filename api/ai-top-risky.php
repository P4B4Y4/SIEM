<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
header('Content-Type: application/json');

// Always return JSON on fatal errors
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
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/../config/config.php';

// Load settings
$settings_path = __DIR__ . '/../config/settings.json';
$settings = [];
if (is_file($settings_path)) {
    $raw = file_get_contents($settings_path);
    $decoded = json_decode((string)$raw, true);
    if (is_array($decoded)) $settings = $decoded;
}
$getSetting = function (string $key, $default = null) use (&$settings) {
    $parts = explode('.', $key);
    $cur = $settings;
    foreach ($parts as $p) {
        if (!is_array($cur) || !array_key_exists($p, $cur)) return $default;
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
$db->query("CREATE TABLE IF NOT EXISTS dashboard_ai_top_risky (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cache_key VARCHAR(64) NOT NULL,
    model VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    payload_json MEDIUMTEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cache_model_provider (cache_key, model, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$cache_key = 'top5_last24h';

if (!$force) {
    $c = $db->prepare('SELECT payload_json, updated_at FROM dashboard_ai_top_risky WHERE cache_key=? AND model=? AND provider=? LIMIT 1');
    $c->bind_param('sss', $cache_key, $ai_model, $ai_provider);
    $c->execute();
    $res = $c->get_result();
    if ($res && $res->num_rows > 0) {
        $row = $res->fetch_assoc();
        $c->close();
        $updated = strtotime((string)$row['updated_at']);
        // TTL 10 minutes
        if ($updated && (time() - $updated) < (10 * 60)) {
            $payload = json_decode((string)($row['payload_json'] ?? 'null'), true);
            if (is_array($payload)) {
                echo json_encode([
                    'success' => true,
                    'cached' => true,
                    'provider' => $ai_provider,
                    'model' => $ai_model,
                    'updated_at' => $row['updated_at'],
                    'items' => $payload
                ]);
                $db->close();
                exit;
            }
        }
    } else {
        $c->close();
    }
}

// Fetch candidates (alerts + events) - last 24h
$candidates = [];

// Alerts table may or may not exist
$tables = $db->query("SHOW TABLES LIKE 'security_alerts'");
if ($tables && $tables->num_rows > 0) {
    $q = $db->query("SELECT alert_id, title, severity, category, timestamp, details
                    FROM security_alerts
                    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                    ORDER BY FIELD(LOWER(severity), 'critical','high','medium','low') ASC, timestamp DESC
                    LIMIT 8");
    if ($q) {
        while ($row = $q->fetch_assoc()) {
            $details = json_decode($row['details'] ?? '{}', true);
            $host = '';
            if (is_array($details)) {
                $host = (string)($details['computer'] ?? $details['host'] ?? $details['agent'] ?? '');
            }
            $candidates[] = [
                'type' => 'alert',
                'id' => (string)$row['alert_id'],
                'title' => (string)$row['title'],
                'severity' => strtolower((string)($row['severity'] ?? 'low')),
                'category' => (string)($row['category'] ?? ''),
                'timestamp' => (string)($row['timestamp'] ?? ''),
                'host' => $host,
                'description' => trim(((string)($row['category'] ?? '') !== '' ? ((string)$row['category'] . ' • ') : '') . (string)$row['title'])
            ];
        }
    }
}

// Events
$q2 = $db->query("SELECT event_id, event_type, severity, source_ip, timestamp
                 FROM security_events
                 WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                 ORDER BY FIELD(LOWER(severity), 'critical','high','medium','low','info') ASC, timestamp DESC
                 LIMIT 8");
if ($q2) {
    while ($row = $q2->fetch_assoc()) {
        $candidates[] = [
            'type' => 'event',
            'id' => (string)$row['event_id'],
            'title' => (string)($row['event_type'] ?? 'Event'),
            'severity' => strtolower((string)($row['severity'] ?? 'low')),
            'category' => '',
            'timestamp' => (string)($row['timestamp'] ?? ''),
            'host' => (string)($row['source_ip'] ?? ''),
            'description' => trim((string)($row['event_type'] ?? 'Event'))
        ];
    }
}

// --- Deterministic scoring + reason strings (no AI) ---
$sevScore = function ($sev) {
    $s = strtolower((string)$sev);
    return match ($s) {
        'critical' => 100,
        'high' => 80,
        'medium' => 60,
        'low' => 40,
        default => 20
    };
};

$safeStr = function ($v): string {
    $t = trim((string)$v);
    $t = preg_replace('/\s+/', ' ', $t);
    return (string)$t;
};

$parseTs = function ($ts): ?int {
    $t = strtotime((string)$ts);
    return $t !== false ? $t : null;
};

// Counts for repetition signals
$hostCounts = [];
$titleCounts = [];
foreach ($candidates as $x) {
    $h = strtolower($safeStr($x['host'] ?? ''));
    $ttl = strtolower($safeStr($x['title'] ?? ''));
    if ($h !== '') $hostCounts[$h] = ($hostCounts[$h] ?? 0) + 1;
    if ($ttl !== '') $titleCounts[$ttl] = ($titleCounts[$ttl] ?? 0) + 1;
}

$riskScore = function (array $x) use ($sevScore, $safeStr, $parseTs, $hostCounts, $titleCounts): int {
    $score = 0;

    // Severity weight
    $score += $sevScore($x['severity'] ?? 'low');

    // Recency (max +30)
    $ts = $parseTs($x['timestamp'] ?? '');
    if ($ts !== null) {
        $age = max(0, time() - $ts);
        if ($age <= 15 * 60) $score += 30;
        elseif ($age <= 60 * 60) $score += 20;
        elseif ($age <= 6 * 60 * 60) $score += 10;
    }

    // Repetition on same host/title (max +35)
    $h = strtolower($safeStr($x['host'] ?? ''));
    $ttl = strtolower($safeStr($x['title'] ?? ''));
    $hc = $h !== '' ? (int)($hostCounts[$h] ?? 0) : 0;
    $tc = $ttl !== '' ? (int)($titleCounts[$ttl] ?? 0) : 0;
    if ($hc >= 3) $score += 18;
    elseif ($hc === 2) $score += 10;
    if ($tc >= 3) $score += 17;
    elseif ($tc === 2) $score += 8;

    // Keyword/category boosts (max +40)
    $text = strtolower($safeStr(($x['category'] ?? '') . ' ' . ($x['title'] ?? '') . ' ' . ($x['description'] ?? '')));
    $boosts = [
        'bruteforce' => 25,
        'brute force' => 25,
        'failed login' => 18,
        'logon failure' => 18,
        'ransom' => 35,
        'cryptominer' => 30,
        'mining' => 18,
        'powershell' => 18,
        'cmd.exe' => 15,
        'mimikatz' => 35,
        'lsass' => 25,
        'service install' => 22,
        'persistence' => 22,
        'tamper' => 22,
        'defender' => 18,
        'exfil' => 30,
        'c2' => 30,
        'beacon' => 25,
        'port scan' => 18,
        'scan' => 10
    ];
    foreach ($boosts as $k => $v) {
        if (str_contains($text, $k)) {
            $score += $v;
            break;
        }
    }

    return $score;
};

$makeReason = function (array $x, int $score) use ($sevScore, $safeStr, $parseTs, $hostCounts, $titleCounts): string {
    $sev = strtolower($safeStr($x['severity'] ?? 'low'));
    $host = $safeStr($x['host'] ?? '');
    $title = $safeStr($x['title'] ?? '');
    $cat = strtolower($safeStr($x['category'] ?? ''));
    $text = strtolower($safeStr(($x['category'] ?? '') . ' ' . ($x['title'] ?? '') . ' ' . ($x['description'] ?? '')));

    $parts = [];
    $parts[] = strtoupper($sev) . ' severity';

    $ts = $parseTs($x['timestamp'] ?? '');
    if ($ts !== null) {
        $ageMins = (int)floor(max(0, time() - $ts) / 60);
        if ($ageMins <= 15) $parts[] = 'very recent';
        elseif ($ageMins <= 60) $parts[] = 'recent';
    }

    $hKey = strtolower($host);
    $tKey = strtolower($title);
    $hc = $hKey !== '' ? (int)($hostCounts[$hKey] ?? 0) : 0;
    $tc = $tKey !== '' ? (int)($titleCounts[$tKey] ?? 0) : 0;
    if ($hc >= 2 && $host !== '') $parts[] = 'multiple items on ' . $host;
    if ($tc >= 2 && $title !== '') $parts[] = 'repeated pattern';

    $tag = '';
    if (str_contains($text, 'bruteforce') || str_contains($text, 'brute force') || str_contains($text, 'failed login') || str_contains($text, 'logon failure')) {
        $tag = 'possible brute-force';
    } elseif (str_contains($text, 'ransom')) {
        $tag = 'possible ransomware';
    } elseif (str_contains($text, 'powershell') || str_contains($text, 'cmd.exe')) {
        $tag = 'suspicious command execution';
    } elseif (str_contains($text, 'mimikatz') || str_contains($text, 'lsass')) {
        $tag = 'credential access indicators';
    } elseif (str_contains($text, 'scan') || str_contains($text, 'port scan')) {
        $tag = 'reconnaissance indicators';
    } elseif ($cat !== '') {
        $tag = $cat;
    }
    if ($tag !== '') $parts[] = $tag;

    // Keep it short-ish
    $reason = implode(' • ', $parts);
    $reason = preg_replace('/\s+/', ' ', (string)$reason);
    if (strlen($reason) > 180) {
        $reason = substr($reason, 0, 180);
    }
    return $reason;
};

// Score + rank
foreach ($candidates as $i => $x) {
    $candidates[$i]['_risk_score'] = $riskScore($x);
}

usort($candidates, function ($a, $b) {
    $sa = (int)($a['_risk_score'] ?? 0);
    $sb = (int)($b['_risk_score'] ?? 0);
    if ($sa === $sb) {
        return strcmp((string)($b['timestamp'] ?? ''), (string)($a['timestamp'] ?? ''));
    }
    return $sb <=> $sa;
});

$candidates = array_slice($candidates, 0, 5);

$items = [];
foreach ($candidates as $x) {
    $score = (int)($x['_risk_score'] ?? 0);
    unset($x['_risk_score']);
    $x['reason'] = $makeReason($x, $score);
    if (!isset($x['description']) || !is_string($x['description'])) {
        $x['description'] = '';
    }
    $items[] = $x;
}

$payload_json = json_encode($items, JSON_UNESCAPED_SLASHES);
if ($payload_json === false) {
    $payload_json = '[]';
}

$ins = $db->prepare('INSERT INTO dashboard_ai_top_risky (cache_key, model, provider, payload_json) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE payload_json=VALUES(payload_json)');
$ins->bind_param('ssss', $cache_key, $ai_model, $ai_provider, $payload_json);
$ins->execute();
$ins->close();

echo json_encode([
    'success' => true,
    'cached' => false,
    'provider' => $ai_provider,
    'model' => $ai_model,
    'items' => $items
]);

$db->close();
