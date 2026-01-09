<?php
/**
 * AI Alert Analysis API (Groq)
 *
 * Returns AI-generated summary + recommended actions for a given alert_id.
 */

session_start();
require_once dirname(__DIR__) . '/config/config.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

header('Content-Type: application/json');

// Avoid empty responses on fatal errors
ini_set('display_errors', '0');
error_reporting(E_ALL);
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) {
            header('Content-Type: application/json');
            http_response_code(500);
        }
        echo json_encode([
            'success' => false,
            'error' => 'Server error: ' . $err['message'],
            'file' => basename($err['file']),
            'line' => $err['line']
        ]);
    }
});

if (!isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

$alert_id = $_GET['alert_id'] ?? '';
if (!$alert_id) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'alert_id required']);
    exit;
}

$force = !empty($_GET['force']);

$ai_enabled = (bool)getSetting('ai.enabled', false);
$ai_provider = (string)getSetting('ai.provider', 'groq');
$ai_model = (string)getSetting('ai.model', 'openai/gpt-oss-20b');
$ai_api_key = (string)getSetting('ai.api_key', '');

if (!$ai_enabled) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'AI is disabled in settings']);
    exit;
}

if ($ai_provider !== 'groq') {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Unsupported AI provider']);
    exit;
}

if (!$ai_api_key) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'AI API key is not configured']);
    exit;
}

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Database connection failed']);
    exit;
}

// Ensure cache table exists
$db->query("CREATE TABLE IF NOT EXISTS alert_ai_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(64) NOT NULL,
    model VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    summary TEXT NULL,
    recommended_actions_json TEXT NULL,
    suggested_commands_json TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_alert_model_provider (alert_id, model, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// Schema migration for older installs
$colCheck = $db->query("SHOW COLUMNS FROM alert_ai_analysis LIKE 'suggested_commands_json'");
if ($colCheck && $colCheck->num_rows === 0) {
    $db->query("ALTER TABLE alert_ai_analysis ADD COLUMN suggested_commands_json TEXT NULL AFTER recommended_actions_json");
}

// If cached, return it
$cache_stmt = $db->prepare('SELECT summary, recommended_actions_json, suggested_commands_json, updated_at FROM alert_ai_analysis WHERE alert_id = ? AND model = ? AND provider = ? LIMIT 1');
$cache_stmt->bind_param('sss', $alert_id, $ai_model, $ai_provider);
$cache_stmt->execute();
$cache_res = $cache_stmt->get_result();
if (!$force && $cache_res && $cache_res->num_rows > 0) {
    $row = $cache_res->fetch_assoc();
    $cache_stmt->close();

    $rec = json_decode($row['recommended_actions_json'] ?? '[]', true);
    $cmds = json_decode($row['suggested_commands_json'] ?? '[]', true);
    if (!is_array($rec)) {
        $rec = [];
    }
    if (!is_array($cmds)) {
        $cmds = [];
    }

    // If cached summary looks like a JSON blob, bypass cache (old broken parse)
    $sum = (string)($row['summary'] ?? '');
    $trim = ltrim($sum);
    if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[') && (count($rec) === 0)) {
        // fall through to recompute
    } else {
    echo json_encode([
        'success' => true,
        'cached' => true,
        'model' => $ai_model,
        'provider' => $ai_provider,
        'summary' => $sum,
        'recommended_actions' => $rec,
        'suggested_commands' => $cmds,
        'updated_at' => $row['updated_at']
    ]);
    exit;
    }
}

// If still invalid JSON, retry once asking for shorter JSON output
if (!is_array($ai_json)) {
    $used_retry = true;
    $retry_short_prompt = $user_prompt . "\n\nIMPORTANT: Output minified JSON ONLY. Keep summary under 200 chars, max 4 actions, max 3 commands.";
    $retry_body2 = json_encode([
        'model' => $ai_model,
        'messages' => [
            ['role' => 'system', 'content' => 'Return ONLY valid minified JSON.'],
            ['role' => 'user', 'content' => $retry_short_prompt]
        ],
        'temperature' => 0.1,
        'max_tokens' => 450
    ], JSON_UNESCAPED_SLASHES);

    $ch3 = curl_init('https://api.groq.com/openai/v1/chat/completions');
    curl_setopt($ch3, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch3, CURLOPT_POST, true);
    curl_setopt($ch3, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch3, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $ai_api_key
    ]);
    curl_setopt($ch3, CURLOPT_POSTFIELDS, $retry_body2);
    $response3 = curl_exec($ch3);
    $http_code3 = curl_getinfo($ch3, CURLINFO_HTTP_CODE);
    curl_close($ch3);

    if ($response3 !== false && $http_code3 >= 200 && $http_code3 < 300) {
        $data3 = json_decode($response3, true);
        $content3 = $data3['choices'][0]['message']['content'] ?? '';
        if (is_string($content3) && trim($content3) !== '') {
            $ai_json = json_decode($content3, true);
        }
    }
}
$cache_stmt->close();

// Load the alert
$stmt = $db->prepare('SELECT alert_id, title, severity, category, description, details, recommended_actions, raw_log, timestamp FROM security_alerts WHERE alert_id = ? LIMIT 1');
$stmt->bind_param('s', $alert_id);
$stmt->execute();
$res = $stmt->get_result();
if (!$res || $res->num_rows === 0) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'Alert not found']);
    exit;
}
$alert = $res->fetch_assoc();
$stmt->close();

$details = json_decode($alert['details'] ?? '{}', true);
$raw_log = json_decode($alert['raw_log'] ?? '{}', true);

// Build a minimal, safe prompt
$computer = $details['computer'] ?? ($raw_log['computer'] ?? 'unknown');
$event_type = $details['event_type'] ?? ($alert['category'] ?? '');

$prompt_payload = [
    'alert_id' => $alert['alert_id'],
    'title' => $alert['title'],
    'severity' => $alert['severity'],
    'category' => $alert['category'],
    'timestamp' => $alert['timestamp'],
    'computer' => $computer,
    'event_type' => $event_type,
    'description' => mb_substr((string)($alert['description'] ?? ''), 0, 1200),
    'raw_log' => mb_substr(json_encode($raw_log, JSON_UNESCAPED_SLASHES), 0, 2000)
];

$system_prompt = "Respond ONLY as valid minified JSON (no markdown, no code fences). Schema: {summary:string, recommended_actions:string[<=6], suggested_commands:any[<=5]}. suggested_commands may be EITHER an array of command strings OR an array of {label,command}. Commands must be SAFE investigation/containment only. Do NOT include reasoning.";
$user_prompt = "Analyze this SIEM alert and propose next steps. Output must be valid JSON only. Input:\n" . json_encode($prompt_payload, JSON_UNESCAPED_SLASHES);

$body = json_encode([
    'model' => $ai_model,
    'messages' => [
        ['role' => 'system', 'content' => $system_prompt],
        ['role' => 'user', 'content' => $user_prompt]
    ],
    'temperature' => 0.1,
    'max_tokens' => 600
], JSON_UNESCAPED_SLASHES);

$ch = curl_init('https://api.groq.com/openai/v1/chat/completions');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'Authorization: Bearer ' . $ai_api_key
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_err = curl_error($ch);
curl_close($ch);

if ($response === false) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'AI request failed', 'details' => $curl_err]);
    exit;
}

if ($http_code < 200 || $http_code >= 300) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'AI request returned HTTP ' . $http_code, 'details' => mb_substr($response, 0, 500)]);
    exit;
}

$data = json_decode($response, true);
if (!is_array($data)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'AI response was not valid JSON', 'details' => mb_substr((string)$response, 0, 500)]);
    exit;
}

$content = $data['choices'][0]['message']['content'] ?? '';
$used_reasoning_fallback = false;
$used_retry = false;
if (!is_string($content) || trim($content) === '') {
    // Some providers may return "reasoning" separately; prefer retry to get actual JSON content
    $reasoning = $data['choices'][0]['message']['reasoning'] ?? '';

    // Retry once with a stricter prompt if we got empty content
    $used_retry = true;
    $retry_body = json_encode([
        'model' => $ai_model,
        'messages' => [
            ['role' => 'system', 'content' => 'Return ONLY valid minified JSON. Do not include reasoning.'],
            ['role' => 'user', 'content' => $user_prompt]
        ],
        'temperature' => 0.1,
        'max_tokens' => 700
    ], JSON_UNESCAPED_SLASHES);

    $ch2 = curl_init('https://api.groq.com/openai/v1/chat/completions');
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch2, CURLOPT_POST, true);
    curl_setopt($ch2, CURLOPT_TIMEOUT, 30);
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
        $content2 = $data2['choices'][0]['message']['content'] ?? '';
        if (is_string($content2) && trim($content2) !== '') {
            $content = $content2;
        }
    }

    // Final fallback: use reasoning as summary content (may not be JSON)
    if ((!is_string($content) || trim($content) === '') && is_string($reasoning) && trim($reasoning) !== '') {
        $content = $reasoning;
        $used_reasoning_fallback = true;
    }
}

if (!is_string($content) || trim($content) === '') {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'AI returned empty response',
        'details' => mb_substr((string)$response, 0, 500)
    ]);
    exit;
}

// Parse the model JSON output
$ai_json = json_decode($content, true);
if (!is_array($ai_json)) {
    // Attempt to salvage if model wrapped JSON in text
    // 1) Extract fenced code block ```json ... ``` (also handles ```json { ... }```)
    if (preg_match('/```\s*(?:json)?\s*([\s\S]*?)\s*```/i', $content, $m)) {
        $inner = trim($m[1]);
        $inner = preg_replace('/^json\s*/i', '', $inner);
        $inner = trim($inner);
        $ai_json = json_decode($inner, true);
    }

    // 2) Extract first JSON object
    $start = strpos($content, '{');
    $end = strrpos($content, '}');
    if ($start !== false && $end !== false && $end > $start) {
        $maybe = substr($content, $start, $end - $start + 1);
        $ai_json = json_decode($maybe, true);
    }

    // 3) Extract first JSON array
    if (!is_array($ai_json)) {
        $startA = strpos($content, '[');
        $endA = strrpos($content, ']');
        if ($startA !== false && $endA !== false && $endA > $startA) {
            $maybeA = substr($content, $startA, $endA - $startA + 1);
            $ai_json = json_decode($maybeA, true);
        }
    }
}


// Normalize alternate schemas from model
if (is_array($ai_json) && empty($ai_json['recommended_actions']) && isset($ai_json['recommendations']) && is_array($ai_json['recommendations'])) {
    $ai_json['recommended_actions'] = $ai_json['recommendations'];
}

$summary = is_array($ai_json) ? (string)($ai_json['summary'] ?? '') : '';

$recommended_actions = [];
if (is_array($ai_json)) {
    if (isset($ai_json['recommended_actions'])) {
        $recommended_actions = $ai_json['recommended_actions'];
    } elseif (isset($ai_json['recommended_actions'])) {
        $recommended_actions = $ai_json['recommended_actions'];
    }
}
if (is_string($recommended_actions) && $recommended_actions !== '') {
    $recommended_actions = [$recommended_actions];
}
if (!is_array($recommended_actions)) {
    $recommended_actions = [];
}
if (count($recommended_actions) > 6) {
    $recommended_actions = array_slice($recommended_actions, 0, 6);
}

if ($summary === '' && count($recommended_actions) > 0) {
    $summary = (string)$recommended_actions[0];
}

$suggested_commands = [];
if (is_array($ai_json)) {
    if (isset($ai_json['suggested_commands'])) {
        $suggested_commands = $ai_json['suggested_commands'];
    } elseif (isset($ai_json['suggested_commands'])) {
        $suggested_commands = $ai_json['suggested_commands'];
    }
}
if (!is_array($suggested_commands)) {
    $suggested_commands = [];
}
if (count($suggested_commands) > 5) {
    $suggested_commands = array_slice($suggested_commands, 0, 5);
}

// Normalize suggested commands format
$normalized_cmds = [];
foreach ($suggested_commands as $c) {
    $label = '';
    $cmd = '';
    if (is_string($c)) {
        $cmd = trim($c);
    } elseif (is_array($c)) {
        $label = isset($c['label']) ? trim((string)$c['label']) : '';
        $cmd = isset($c['command']) ? trim((string)$c['command']) : '';
    } else {
        continue;
    }
    if ($cmd === '' && $label !== '') {
        $cmd = $label;
        $label = '';
    }
    if ($cmd === '') {
        continue;
    }
    // Drop obviously truncated commands
    if (substr($cmd, -1) === '|' || substr($cmd, -1) === '\\' || preg_match('/\bWorkin$/i', $cmd)) {
        continue;
    }
    // Keep commands single-line to avoid breaking UI/agent parsing
    $cmd = preg_replace("/\r|\n/", ' ', $cmd);
    // Disallow empty after cleanup
    if (trim($cmd) === '') {
        continue;
    }
    // Limit length to reduce risk
    if (strlen($label) > 120) $label = substr($label, 0, 120);
    if (strlen($cmd) > 400) $cmd = substr($cmd, 0, 400);
    $normalized_cmds[] = ['label' => $label !== '' ? $label : 'Command', 'command' => $cmd];
}

// If the model output was low-quality (reasoning fallback / retries) and we still didn't get clean structure,
// do not cache to avoid sticky bad results.
$should_cache = !($used_reasoning_fallback);
if ($used_retry && ($summary === '' || (count($recommended_actions) === 0 && count($normalized_cmds) === 0))) {
    $should_cache = false;
}

// Don't cache commands if we couldn't parse them cleanly
$cache_cmds = true;
if (!is_array($normalized_cmds)) {
    $cache_cmds = false;
}

if ($summary === '' && count($recommended_actions) === 0 && count($normalized_cmds) === 0) {
    // Fall back to plain-text summary instead of failing hard
    $summary = trim(preg_replace('/\s+/', ' ', strip_tags((string)$content)));
    if ($summary === '') {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'AI returned empty response'
        ]);
        exit;
    }
    $summary = mb_substr($summary, 0, 800);
}

// Cache
$rec_json = json_encode(array_values(array_filter($recommended_actions, fn($x) => is_string($x) && $x !== '')));
if ($rec_json === false) {
    $rec_json = '[]';
}
$cmd_json = json_encode($normalized_cmds);
if ($cmd_json === false) {
    $cmd_json = '[]';
    $cache_cmds = false;
}
if ($should_cache) {
    $ins = $db->prepare('INSERT INTO alert_ai_analysis (alert_id, model, provider, summary, recommended_actions_json, suggested_commands_json) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE summary=VALUES(summary), recommended_actions_json=VALUES(recommended_actions_json), suggested_commands_json=VALUES(suggested_commands_json)');
    if (!$cache_cmds) {
        $cmd_json = '[]';
    }
    $ins->bind_param('ssssss', $alert_id, $ai_model, $ai_provider, $summary, $rec_json, $cmd_json);
    $ins->execute();
    $ins->close();
}

echo json_encode([
    'success' => true,
    'cached' => false,
    'model' => $ai_model,
    'provider' => $ai_provider,
    'summary' => $summary,
    'recommended_actions' => json_decode($rec_json, true) ?? [],
    'suggested_commands' => json_decode($cmd_json, true) ?? []
]);
