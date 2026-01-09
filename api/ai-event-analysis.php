<?php
/**
 * AI Event Analysis API (Groq)
 *
 * Returns AI-generated summary + recommended actions for a given event_id.
 */

session_start();
require_once dirname(__DIR__) . '/config/config.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

header('Content-Type: application/json');

if (!isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

$event_id = (int)($_GET['event_id'] ?? 0);
if (!$event_id) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'event_id required']);
    exit;
}

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
$db->query("CREATE TABLE IF NOT EXISTS event_ai_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    model VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    summary TEXT NULL,
    recommended_actions_json TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_event_model_provider (event_id, model, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// If cached, return it
$cache_stmt = $db->prepare('SELECT summary, recommended_actions_json, updated_at FROM event_ai_analysis WHERE event_id = ? AND model = ? AND provider = ? LIMIT 1');
$cache_stmt->bind_param('iss', $event_id, $ai_model, $ai_provider);
$cache_stmt->execute();
$cache_res = $cache_stmt->get_result();
if ($cache_res && $cache_res->num_rows > 0) {
    $row = $cache_res->fetch_assoc();
    $cache_stmt->close();
    echo json_encode([
        'success' => true,
        'cached' => true,
        'model' => $ai_model,
        'provider' => $ai_provider,
        'summary' => $row['summary'] ?? '',
        'recommended_actions' => json_decode($row['recommended_actions_json'] ?? '[]', true) ?? [],
        'updated_at' => $row['updated_at']
    ]);
    exit;
}
$cache_stmt->close();

// Load the event
$stmt = $db->prepare('SELECT * FROM security_events WHERE event_id = ? LIMIT 1');
$stmt->bind_param('i', $event_id);
$stmt->execute();
$res = $stmt->get_result();
if (!$res || $res->num_rows === 0) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'Event not found']);
    exit;
}
$event = $res->fetch_assoc();
$stmt->close();

$raw_log_str = (string)($event['raw_log'] ?? '');
$event_data_str = (string)($event['event_data'] ?? '');

$prompt_payload = [
    'event_id' => (int)$event['event_id'],
    'timestamp' => $event['timestamp'] ?? null,
    'event_type' => $event['event_type'] ?? null,
    'severity' => $event['severity'] ?? null,
    'source_ip' => $event['source_ip'] ?? null,
    'dest_ip' => $event['dest_ip'] ?? null,
    'protocol' => $event['protocol'] ?? null,
    'process_name' => $event['process_name'] ?? null,
    'file_path' => $event['file_path'] ?? null,
    'user_account' => $event['user_account'] ?? null,
    'event_data' => mb_substr($event_data_str, 0, 1200),
    'raw_log' => mb_substr($raw_log_str, 0, 2000)
];

$system_prompt = "You are a SOC assistant. You must respond ONLY in JSON with keys: summary (string), recommended_actions (array of strings). Keep it concise and actionable.";
$user_prompt = "Analyze this SIEM EVENT and propose next steps. JSON input:\n" . json_encode($prompt_payload, JSON_UNESCAPED_SLASHES);

$body = json_encode([
    'model' => $ai_model,
    'messages' => [
        ['role' => 'system', 'content' => $system_prompt],
        ['role' => 'user', 'content' => $user_prompt]
    ],
    'temperature' => 0.2,
    'max_tokens' => 500
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
$content = $data['choices'][0]['message']['content'] ?? '';

$ai_json = json_decode($content, true);
if (!is_array($ai_json)) {
    $start = strpos($content, '{');
    $end = strrpos($content, '}');
    if ($start !== false && $end !== false && $end > $start) {
        $maybe = substr($content, $start, $end - $start + 1);
        $ai_json = json_decode($maybe, true);
    }
}

$summary = is_array($ai_json) ? (string)($ai_json['summary'] ?? '') : '';
$recommended_actions = is_array($ai_json) ? ($ai_json['recommended_actions'] ?? []) : [];
if (!is_array($recommended_actions)) {
    $recommended_actions = [];
}

if ($summary === '' && count($recommended_actions) === 0) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'AI returned empty/invalid JSON response',
        'details' => mb_substr((string)$content, 0, 500)
    ]);
    exit;
}

$rec_json = json_encode(array_values(array_filter($recommended_actions, fn($x) => is_string($x) && $x !== '')));
$ins = $db->prepare('INSERT INTO event_ai_analysis (event_id, model, provider, summary, recommended_actions_json) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE summary=VALUES(summary), recommended_actions_json=VALUES(recommended_actions_json)');
$ins->bind_param('issss', $event_id, $ai_model, $ai_provider, $summary, $rec_json);
$ins->execute();
$ins->close();

echo json_encode([
    'success' => true,
    'cached' => false,
    'model' => $ai_model,
    'provider' => $ai_provider,
    'summary' => $summary,
    'recommended_actions' => json_decode($rec_json, true) ?? []
]);
