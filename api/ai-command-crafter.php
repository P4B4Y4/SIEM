<?php
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

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'POST required']);
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

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid JSON body']);
    exit;
}

$agent = trim((string)($input['agent'] ?? ''));
$intent = trim((string)($input['intent'] ?? ''));
$context = $input['context'] ?? null;

if ($intent === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'intent required']);
    exit;
}

// Keep context small to avoid prompt bloat.
$context_json = '';
if ($context !== null) {
    try {
        $context_json = json_encode($context, JSON_UNESCAPED_SLASHES);
        if ($context_json !== false && strlen($context_json) > 4000) {
            $context_json = substr($context_json, 0, 4000);
        }
    } catch (Exception $e) {
        $context_json = '';
    }
}

$command_guide = [
    'prefix' => 'rt:',
    'notes' => [
        'All commands sent to the agent from Remote Terminal are prefixed with rt: in the API call.',
        'The agent supports special commands like screenshot, download:<path>, upload:<dest>|<base64>.',
        'If user wants raw Windows shell execution, return a safe single-line shell command (cmd or powershell).',
        'Prefer built-in agent commands if they exist; otherwise return a shell command.'
    ],
    'examples' => [
        ['intent' => 'take screenshot', 'command' => 'screenshot'],
        ['intent' => 'download hosts file', 'command' => 'download:C:\\Windows\\System32\\drivers\\etc\\hosts'],
        ['intent' => 'list running processes', 'command' => 'tasklist'],
        ['intent' => 'show ip addresses', 'command' => 'ipconfig /all'],
        ['intent' => 'show who am i', 'command' => 'whoami'],
        ['intent' => 'list services', 'command' => 'sc query type= service state= all'],
        ['intent' => 'restart mysql service', 'command' => 'net stop MySQL && net start MySQL'],
        ['intent' => 'show scheduled tasks', 'command' => 'schtasks /query /fo LIST /v'],
        ['intent' => 'kill pid 1234', 'command' => 'taskkill /PID 1234 /F'],
    ]
];

$system_prompt = "You are an assistant that crafts remote terminal commands for a Windows agent. You must output ONLY valid minified JSON (no markdown).\n" .
    "Schema: {suggested_command:string, command_type:string, needs_prefix:boolean, explanation:string, warnings:string[]}.\n" .
    "command_type must be one of: agent, shell_cmd, shell_powershell.\n" .
    "needs_prefix indicates whether the UI should send this as rt:<command> (true) or as raw <command> (false).\n" .
    "Rules: Prefer existing agent commands if applicable. Keep suggested_command single-line. If destructive (delete, format, ransomware, disable security), include warnings and suggest a safer alternative if possible.";

$payload = [
    'agent' => $agent !== '' ? $agent : null,
    'intent' => $intent,
    'context' => $context_json !== '' ? $context : null,
    'terminal_command_conventions' => $command_guide
];

$user_prompt = "Craft the best command for this user intent, compatible with our remote terminal + agent. Input JSON:\n" . json_encode($payload, JSON_UNESCAPED_SLASHES);

$body = json_encode([
    'model' => $ai_model,
    'messages' => [
        ['role' => 'system', 'content' => $system_prompt],
        ['role' => 'user', 'content' => $user_prompt]
    ],
    'temperature' => 0.2,
    'max_tokens' => 450
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

$ai_json = json_decode((string)$content, true);
if (!is_array($ai_json)) {
    // salvage wrapped JSON
    $start = strpos((string)$content, '{');
    $end = strrpos((string)$content, '}');
    if ($start !== false && $end !== false && $end > $start) {
        $maybe = substr((string)$content, $start, $end - $start + 1);
        $ai_json = json_decode($maybe, true);
    }
}

if (!is_array($ai_json)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'AI returned invalid JSON', 'details' => mb_substr((string)$content, 0, 500)]);
    exit;
}

$suggested_command = trim((string)($ai_json['suggested_command'] ?? ''));
$command_type = trim((string)($ai_json['command_type'] ?? ''));
$needs_prefix = (bool)($ai_json['needs_prefix'] ?? true);
$explanation = trim((string)($ai_json['explanation'] ?? ''));
$warnings = $ai_json['warnings'] ?? [];

if ($suggested_command === '') {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'AI returned empty suggested_command', 'details' => mb_substr((string)$content, 0, 500)]);
    exit;
}

// Normalize
$suggested_command = preg_replace("/\r|\n/", ' ', $suggested_command);
if (strlen($suggested_command) > 600) {
    $suggested_command = substr($suggested_command, 0, 600);
}

if (!in_array($command_type, ['agent', 'shell_cmd', 'shell_powershell'], true)) {
    $command_type = 'agent';
}

if (!is_array($warnings)) {
    $warnings = [];
}
$warnings = array_values(array_filter($warnings, fn($w) => is_string($w) && trim($w) !== ''));
if (count($warnings) > 6) {
    $warnings = array_slice($warnings, 0, 6);
}

echo json_encode([
    'success' => true,
    'model' => $ai_model,
    'provider' => $ai_provider,
    'suggested_command' => $suggested_command,
    'command_type' => $command_type,
    'needs_prefix' => $needs_prefix,
    'explanation' => $explanation,
    'warnings' => $warnings
]);
