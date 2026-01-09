<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
header('Content-Type: application/json');

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

// Load settings.json
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

$host = isset($_GET['host']) ? trim((string)$_GET['host']) : '';
$hours = isset($_GET['hours']) ? max(1, min(72, (int)$_GET['hours'])) : 12;
$force = isset($_GET['force']) && $_GET['force'] === '1';
$debug = isset($_GET['debug']) && $_GET['debug'] === '1';

if ($host === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'host parameter required']);
    exit;
}

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Database connection failed']);
    exit;
}

// Cache table
$db->query("CREATE TABLE IF NOT EXISTS incident_story_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cache_key VARCHAR(128) NOT NULL,
    model VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    payload_json MEDIUMTEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cache_model_provider (cache_key, model, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$cache_key = 'host:' . strtolower($host) . '|h:' . $hours;

if (!$force) {
    $c = $db->prepare('SELECT payload_json, updated_at FROM incident_story_cache WHERE cache_key=? AND model=? AND provider=? LIMIT 1');
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
                    'payload' => $payload
                ]);
                $db->close();
                exit;
            }
        }
    } else {
        $c->close();
    }
}

// Collect timeline items
$timeline = [];

// Alerts (if exists)
$tables = $db->query("SHOW TABLES LIKE 'security_alerts'");
if ($tables && $tables->num_rows > 0) {
    $stmt = $db->prepare("SELECT alert_id, title, severity, category, timestamp, details
                          FROM security_alerts
                          WHERE timestamp >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                          ORDER BY timestamp DESC
                          LIMIT 30");
    $stmt->bind_param('i', $hours);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $details = json_decode($row['details'] ?? '{}', true);
        $h = '';
        if (is_array($details)) {
            $h = (string)($details['computer'] ?? $details['host'] ?? $details['agent'] ?? '');
        }
        if ($h === '' || strcasecmp($h, $host) !== 0) {
            continue;
        }
        $timeline[] = [
            'type' => 'alert',
            'id' => (string)$row['alert_id'],
            'timestamp' => (string)$row['timestamp'],
            'severity' => strtolower((string)($row['severity'] ?? 'low')),
            'title' => (string)($row['title'] ?? 'Alert'),
            'category' => (string)($row['category'] ?? ''),
        ];
    }
    $stmt->close();
}

// Events - try matching by source_ip or agent_id to the host string
$stmt2 = $db->prepare("SELECT event_id, event_type, severity, source_ip, agent_id, timestamp
                       FROM security_events
                       WHERE timestamp >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                       AND (source_ip = ? OR agent_id = ?)
                       ORDER BY timestamp DESC
                       LIMIT 50");
$stmt2->bind_param('iss', $hours, $host, $host);
$stmt2->execute();
$res2 = $stmt2->get_result();
while ($row = $res2->fetch_assoc()) {
    $timeline[] = [
        'type' => 'event',
        'id' => (string)$row['event_id'],
        'timestamp' => (string)$row['timestamp'],
        'severity' => strtolower((string)($row['severity'] ?? 'low')),
        'title' => (string)($row['event_type'] ?? 'Event'),
        'source' => (string)($row['source_ip'] ?? ''),
    ];
}
$stmt2->close();

// Sort chronological (oldest -> newest)
usort($timeline, function ($a, $b) {
    return strcmp((string)($a['timestamp'] ?? ''), (string)($b['timestamp'] ?? ''));
});

// De-duplicate repeated items (common when the same alert/event is emitted many times)
$deduped = [];
$seen = [];
foreach ($timeline as $it) {
    $key = strtolower((string)($it['type'] ?? '')) . '|' . strtolower((string)($it['severity'] ?? '')) . '|' . strtolower((string)($it['title'] ?? ''));
    if (isset($seen[$key])) {
        continue;
    }
    $seen[$key] = true;
    $deduped[] = $it;
}
$timeline = $deduped;

// Trim to last 25 entries to limit tokens
if (count($timeline) > 25) {
    $timeline = array_slice($timeline, -25);
}

// If AI not available, return a basic non-AI payload
if (!$ai_enabled || $ai_provider !== 'groq' || !$ai_api_key) {
    $payload = [
        'story_title' => 'Incident timeline for ' . $host,
        'story' => 'AI is disabled; showing related activity timeline only.',
        'timeline' => $timeline,
        'next_steps' => [
            'Review the timeline for repeated critical/high items.',
            'Validate whether the host shows signs of compromise or system failure.',
            'Collect additional telemetry (process list, disk, auth logs) as needed.'
        ]
    ];

    echo json_encode(['success' => true, 'cached' => false, 'provider' => $ai_provider, 'model' => $ai_model, 'payload' => $payload]);
    $db->close();
    exit;
}

$system_prompt = "Return ONLY valid minified JSON. Do NOT include any other text. No markdown, no code fences, no explanations.\n\nSchema: {\"story_title\":string,\"story\":string,\"timeline\":string[<=12],\"next_steps\":string[<=7],\"suggested_commands\":[{\"label\":string,\"command\":string}<=6]}.\n\nExample (format only): {\"story_title\":\"Incident story for HOST\",\"story\":\"...\",\"timeline\":[\"t1\",\"t2\"],\"next_steps\":[\"s1\",\"s2\"],\"suggested_commands\":[{\"label\":\"Check disk\",\"command\":\"chkdsk C: /f /r\"}]}.\n\nWrite an incident story for the host based on the SEQUENCE of items. timeline[] are short bullets describing key moments in order. next_steps[] are practical investigation/containment steps. suggested_commands[] are SAFE investigation/triage commands (read-only where possible). Commands must be single-line. Output must start with '{' and end with '}'.";

// Provide compact input
$input = [
    'host' => $host,
    'window_hours' => $hours,
    'items' => $timeline
];

$user_prompt = json_encode($input, JSON_UNESCAPED_SLASHES);

$body = json_encode([
    'model' => $ai_model,
    'messages' => [
        ['role' => 'system', 'content' => $system_prompt],
        ['role' => 'user', 'content' => $user_prompt]
    ],
    'temperature' => 0.0,
    'max_tokens' => 320
], JSON_UNESCAPED_SLASHES);

$ch = curl_init('https://api.groq.com/openai/v1/chat/completions');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 25);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'Authorization: Bearer ' . $ai_api_key
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_err = curl_error($ch);
curl_close($ch);

if ($response === false || $http_code < 200 || $http_code >= 300) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'AI request failed', 'details' => $curl_err ? $curl_err : mb_substr((string)$response, 0, 400)]);
    $db->close();
    exit;
}

$data = json_decode($response, true);
$content = is_array($data) ? ($data['choices'][0]['message']['content'] ?? '') : '';
if (!is_string($content) || trim($content) === '') {
    $reasoning = is_array($data) ? ($data['choices'][0]['message']['reasoning'] ?? '') : '';
    if (is_string($reasoning) && trim($reasoning) !== '') $content = $reasoning;
}

// Extract JSON
$extractJsonObject = function (string $text): string {
    $t = trim($text);
    // Remove code fences if present
    $t = preg_replace('/```(?:json)?/i', '', $t);
    $t = trim($t);
    // Try to locate the first JSON object
    $start = strpos($t, '{');
    $end = strrpos($t, '}');
    if ($start === false || $end === false || $end <= $start) {
        return $t;
    }
    return substr($t, $start, $end - $start + 1);
};

$t = $extractJsonObject((string)$content);
$payload = json_decode($t, true);

// Retry once if invalid
if (!is_array($payload)) {
    $retry_body = json_encode([
        'model' => $ai_model,
        'messages' => [
            ['role' => 'system', 'content' => 'Return ONLY valid minified JSON. No extra text. Output must start with { and end with }.'],
            ['role' => 'user', 'content' => $user_prompt]
        ],
        'temperature' => 0.0,
        'max_tokens' => 320
    ], JSON_UNESCAPED_SLASHES);

    $ch2 = curl_init('https://api.groq.com/openai/v1/chat/completions');
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch2, CURLOPT_POST, true);
    curl_setopt($ch2, CURLOPT_TIMEOUT, 25);
    curl_setopt($ch2, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $ai_api_key
    ]);
    curl_setopt($ch2, CURLOPT_POSTFIELDS, $retry_body);
    $response2 = curl_exec($ch2);
    $http_code2 = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
    curl_close($ch2);

    if ($response2 !== false && $http_code2 >= 200 && $http_code2 < 300) {
        $data2 = json_decode($response2, true);
        $content2 = is_array($data2) ? ($data2['choices'][0]['message']['content'] ?? '') : '';
        $t2 = $extractJsonObject((string)$content2);
        $payload = json_decode($t2, true);
    }
}

// Repair attempt: if model returned *almost* JSON, ask the model to fix it (cheap, short)
if (!is_array($payload) && is_string($t) && trim($t) !== '') {
    $repair_body = json_encode([
        'model' => $ai_model,
        'messages' => [
            ['role' => 'system', 'content' => 'You are a JSON repair tool. Output ONLY corrected minified JSON.'],
            ['role' => 'user', 'content' => "Fix this into valid JSON matching schema {story_title:string, story:string, timeline:string[<=12], next_steps:string[<=7]} and output ONLY the JSON: \n" . $t]
        ],
        'temperature' => 0.0,
        'max_tokens' => 320
    ], JSON_UNESCAPED_SLASHES);

    $ch3 = curl_init('https://api.groq.com/openai/v1/chat/completions');
    curl_setopt($ch3, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch3, CURLOPT_POST, true);
    curl_setopt($ch3, CURLOPT_TIMEOUT, 25);
    curl_setopt($ch3, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $ai_api_key
    ]);
    curl_setopt($ch3, CURLOPT_POSTFIELDS, $repair_body);
    $response3 = curl_exec($ch3);
    $http_code3 = curl_getinfo($ch3, CURLINFO_HTTP_CODE);
    curl_close($ch3);

    if ($response3 !== false && $http_code3 >= 200 && $http_code3 < 300) {
        $data3 = json_decode($response3, true);
        $content3 = is_array($data3) ? ($data3['choices'][0]['message']['content'] ?? '') : '';
        $t3 = $extractJsonObject((string)$content3);
        $payload = json_decode($t3, true);
    }
}

$used_fallback = false;

if (!is_array($payload)) {
    $used_fallback = true;

    $sevRank = function (string $sev): int {
        $s = strtolower($sev);
        if ($s === 'critical') return 4;
        if ($s === 'high') return 3;
        if ($s === 'medium') return 2;
        return 1;
    };

    $uniqueTitles = [];
    $maxSev = 'low';
    foreach ($timeline as $it) {
        $ttl = trim((string)($it['title'] ?? ''));
        if ($ttl !== '') {
            $uniqueTitles[strtolower($ttl)] = $ttl;
        }
        $sev = (string)($it['severity'] ?? 'low');
        if ($sevRank($sev) > $sevRank($maxSev)) $maxSev = $sev;
    }
    $topTitles = array_values($uniqueTitles);
    if (count($topTitles) > 3) $topTitles = array_slice($topTitles, 0, 3);

    $firstTs = count($timeline) > 0 ? (string)($timeline[0]['timestamp'] ?? '') : '';
    $lastTs = count($timeline) > 0 ? (string)($timeline[count($timeline) - 1]['timestamp'] ?? '') : '';
    $windowText = ($firstTs !== '' && $lastTs !== '') ? ($firstTs . ' to ' . $lastTs) : ('last ' . $hours . 'h');
    $headline = strtoupper($maxSev) . ' activity trend';
    if (count($topTitles) > 0) {
        $headline .= ': ' . implode(', ', $topTitles);
    }

    $payload = [
        'story_title' => 'Incident story for ' . $host,
        'story' => $headline . ' on ' . $host . ' (' . $windowText . '). This looks like a system health degradation pattern rather than a single isolated alert; verify whether it is caused by resource exhaustion, hardware failure, or malicious activity.',
        'timeline' => array_map(function ($x) {
            $s = strtoupper((string)($x['severity'] ?? ''));
            $t = (string)($x['title'] ?? '');
            $ts = (string)($x['timestamp'] ?? '');
            return $ts . ' • ' . $s . ' • ' . $t;
        }, array_slice($timeline, -12)),
        'next_steps' => [
            'Validate whether disk/memory/CPU anomalies are sustained: capture current utilization and top processes.',
            'Check system logs for disk errors and hardware warnings; run disk health checks and verify free space.',
            'If you suspect ransomware or crypto-mining, isolate the host and scan for recent mass file changes and suspicious processes.',
            'Collect triage artifacts (process list, autoruns, network connections) and preserve logs for investigation.'
        ],
        'suggested_commands' => [
            ['label' => 'Disk status (SMART if available)', 'command' => 'wmic diskdrive get status'],
            ['label' => 'Top processes by CPU', 'command' => 'powershell -NoProfile -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,CPU,WS"'],
            ['label' => 'Top processes by memory', 'command' => 'powershell -NoProfile -Command "Get-Process | Sort-Object WS -Descending | Select-Object -First 10 Name,Id,WS,CPU"'],
            ['label' => 'Recent System log disk events', 'command' => 'powershell -NoProfile -Command "Get-WinEvent -LogName System -MaxEvents 200 | Where-Object { $_.Message -match \"disk\" } | Select-Object -First 20 TimeCreated,Id,LevelDisplayName,Message"'],
            ['label' => 'Recent file changes (last 1h)', 'command' => 'powershell -NoProfile -Command "Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) } | Select-Object -First 50 FullName,LastWriteTime"']
        ]
    ];
}

// Attach raw timeline for UI inspection
$payload['raw_timeline'] = $timeline;

$payload_json = json_encode($payload, JSON_UNESCAPED_SLASHES);
if ($payload_json === false) {
    $payload_json = '{}';
}

// Do not cache fallback payloads (prevents persistent "Unable to parse" results)
if (!$used_fallback) {
    $ins = $db->prepare('INSERT INTO incident_story_cache (cache_key, model, provider, payload_json) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE payload_json=VALUES(payload_json)');
    $ins->bind_param('ssss', $cache_key, $ai_model, $ai_provider, $payload_json);
    $ins->execute();
    $ins->close();
}

$out = [
    'success' => true,
    'cached' => false,
    'provider' => $ai_provider,
    'model' => $ai_model,
    'payload' => $payload
];

if ($debug) {
    $out['debug'] = [
        'used_fallback' => $used_fallback,
        'http_code' => $http_code,
        'content_snip' => mb_substr((string)$content, 0, 800),
        'extracted_json_snip' => mb_substr((string)$t, 0, 800)
    ];
}

echo json_encode($out);

$db->close();
