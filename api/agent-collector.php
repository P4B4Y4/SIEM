<?php
/**
 * SIEM Agent Collector - HTTP API Version
 * Agents POST events to this endpoint
 * Automatically evaluates events against threat detection rules
 */

header('Content-Type: application/json');

require_once dirname(__DIR__) . '/config/config.php';

// Noise control settings (server-side)
$NOISE_BOOT_WINDOW_SECONDS = 300;
$NOISE_DEDUP_WINDOW_SECONDS = 10;
$NOISE_RATE_WINDOW_SECONDS = 10;
$NOISE_RATE_MAX_EVENTS_PER_WINDOW = 500;

// Get the event data
$input = file_get_contents('php://input');
$event = json_decode($input, true);

if (!$event) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

// Connect to database
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);

if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

// Load threat detection engine
require_once dirname(__DIR__) . '/includes/threat_detection.php';
$detection_engine = new ThreatDetectionEngine($db);

// Load log analyzer
require_once dirname(__DIR__) . '/includes/log_analyzer.php';
$analyzer = new LogAnalyzer($db);

// Store event
try {
    $timestamp = $event['timestamp'] ?? date('Y-m-d H:i:s');
    $event_type = $event['event_type'] ?? $event['log_type'] ?? 'windows_event';
    $severity = $event['severity'] ?? 'info';
    $source_ip = $event['computer'] ?? '0.0.0.0';
    $process_name = $event['source'] ?? 'unknown';
    $raw_parts = [];
    $raw_parts[] = $event['what_happened'] ?? '';
    $raw_parts[] = $event['description'] ?? '';
    $raw_parts[] = $event['message'] ?? '';
    if (!empty($event['registry_path'])) {
        $raw_parts[] = 'registry_path=' . $event['registry_path'];
    }
    if (!empty($event['file_path'])) {
        $raw_parts[] = 'file_path=' . $event['file_path'];
    }
    $raw_log = substr(trim(implode(' | ', array_filter($raw_parts, fn($v) => $v !== null && $v !== ''))), 0, 1000);
    $user_account = $event['agent'] ?? 'unknown';
    $event_json = json_encode($event);

    // ------------------------
    // Server-side noise controls
    // ------------------------
    // Identify host (best-effort). Current agents often send computer/agent fields.
    $host_id = (string)($event['agent'] ?? ($event['computer'] ?? ($event['hostname'] ?? 'unknown')));
    $host_hash = substr(hash('sha256', $host_id), 0, 16);

    // Detect noisy event classes (heuristic based on event_type/raw content)
    $event_type_lc = strtolower((string)$event_type);
    $raw_log_lc = strtolower((string)$raw_log);
    $is_registry_noise = (
        str_contains($event_type_lc, 'registry') ||
        str_contains($raw_log_lc, 'hklm') ||
        str_contains($raw_log_lc, 'hkcu') ||
        str_contains($raw_log_lc, 'currentcontrolset') ||
        str_contains($raw_log_lc, 'registry_path=')
    );
    $is_filemod_noise =
        str_contains($event_type_lc, 'file_modification')
        || (
            str_contains($event_type_lc, 'file') &&
            (str_contains($event_type_lc, 'modify') || str_contains($event_type_lc, 'change') || str_contains($event_type_lc, 'write'))
        )
        || str_contains($raw_log_lc, 'file_path=')
        || (str_contains($raw_log_lc, 'file') && str_contains($raw_log_lc, 'mod'));

    // Parse timestamp as epoch (fallback: now)
    $event_ts = strtotime($timestamp);
    if ($event_ts === false) {
        $event_ts = time();
    }

    // Boot-burst suppression based on host last_seen gap (file-based, no DB schema changes)
    $state_dir = dirname(__DIR__) . '/data/noise_state';
    if (!is_dir($state_dir)) {
        @mkdir($state_dir, 0775, true);
    }
    $last_seen_file = $state_dir . '/last_seen_' . $host_hash . '.json';
    $last_seen = 0;
    if (is_file($last_seen_file)) {
        $prev = json_decode(@file_get_contents($last_seen_file), true);
        if (is_array($prev) && isset($prev['last_seen'])) {
            $last_seen = (int)$prev['last_seen'];
        }
    }
    @file_put_contents($last_seen_file, json_encode(['last_seen' => $event_ts]));

    // Boot/reconnect window: start a suppression window when a host first appears after being "offline".
    // Use a persistent boot-window file so suppression remains consistent for the entire window.
    $boot_file = $state_dir . '/boot_window_' . $host_hash . '.json';
    $boot_state = is_file($boot_file) ? json_decode(@file_get_contents($boot_file), true) : null;
    $boot_start = is_array($boot_state) && isset($boot_state['start']) ? (int)$boot_state['start'] : 0;

    $offline_gap = ($last_seen > 0) ? ($event_ts - $last_seen) : 0;
    $should_start_boot_window = ($boot_start === 0) || ($offline_gap >= 120);
    if ($should_start_boot_window) {
        $boot_start = $event_ts;
        $boot_state = ['start' => $boot_start, 'suppressed' => 0];
        @file_put_contents($boot_file, json_encode($boot_state));
    }

    $in_boot_window = ($boot_start > 0) && (($event_ts - $boot_start) <= $NOISE_BOOT_WINDOW_SECONDS);
    if ($in_boot_window && ($is_registry_noise || $is_filemod_noise)) {
        if (is_file($boot_file)) {
            $boot_state = json_decode(@file_get_contents($boot_file), true);
        }
        $boot_state = is_array($boot_state) ? $boot_state : ['start' => $boot_start, 'suppressed' => 0];

        if (($event_ts - $boot_start) <= $NOISE_BOOT_WINDOW_SECONDS) {
            $boot_state = json_decode(@file_get_contents($boot_file), true);
            $boot_state = is_array($boot_state) ? $boot_state : ['start' => $boot_start, 'suppressed' => 0];
            $boot_state['suppressed'] = (int)($boot_state['suppressed'] ?? 0) + 1;
            @file_put_contents($boot_file, json_encode($boot_state));

            http_response_code(200);
            echo json_encode([
                'status' => 'ok',
                'message' => 'Suppressed boot-burst noise',
                'suppressed' => true
            ]);
            $db->close();
            exit;
        }
    }

    // Dedup within short window (file-based)
    $dedup_file = $state_dir . '/dedup_' . $host_hash . '.json';
    $dedup_state = is_file($dedup_file) ? json_decode(@file_get_contents($dedup_file), true) : [];
    if (!is_array($dedup_state)) {
        $dedup_state = [];
    }
    $dedup_key = substr(hash('sha256', $event_type_lc . '|' . $raw_log_lc), 0, 16);
    $last_key_ts = (int)($dedup_state[$dedup_key] ?? 0);
    if ($last_key_ts > 0 && ($event_ts - $last_key_ts) <= $NOISE_DEDUP_WINDOW_SECONDS) {
        http_response_code(200);
        echo json_encode([
            'status' => 'ok',
            'message' => 'Deduplicated',
            'suppressed' => true
        ]);
        $db->close();
        exit;
    }
    $dedup_state[$dedup_key] = $event_ts;
    // Keep state small
    if (count($dedup_state) > 1000) {
        $dedup_state = array_slice($dedup_state, -500, null, true);
    }
    @file_put_contents($dedup_file, json_encode($dedup_state));

    // Per-host rate limit (file-based)
    $rate_file = $state_dir . '/rate_' . $host_hash . '.json';
    $rate_state = is_file($rate_file) ? json_decode(@file_get_contents($rate_file), true) : null;
    $rate_state = is_array($rate_state) ? $rate_state : ['start' => $event_ts, 'count' => 0];
    if (($event_ts - (int)$rate_state['start']) > $NOISE_RATE_WINDOW_SECONDS) {
        $rate_state = ['start' => $event_ts, 'count' => 0];
    }
    $rate_state['count'] = (int)$rate_state['count'] + 1;
    @file_put_contents($rate_file, json_encode($rate_state));
    if ((int)$rate_state['count'] > $NOISE_RATE_MAX_EVENTS_PER_WINDOW && ($is_registry_noise || $is_filemod_noise)) {
        http_response_code(200);
        echo json_encode([
            'status' => 'ok',
            'message' => 'Rate limited noisy events',
            'suppressed' => true
        ]);
        $db->close();
        exit;
    }
    
    $stmt = $db->prepare("
        INSERT INTO security_events 
        (timestamp, event_type, severity, source_ip, process_name, raw_log, event_data, user_account, agent_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
    ");
    
    $stmt->bind_param("ssssssss",
        $timestamp,
        $event_type,
        $severity,
        $source_ip,
        $process_name,
        $raw_log,
        $event_json,
        $user_account
    );
    
    if ($stmt->execute()) {
        // Event stored successfully, now evaluate it against threat detection rules
        $normalized_log = [
            'timestamp' => $timestamp,
            'event_id' => $event['event_id'] ?? ($event['windows_event_id'] ?? ($event['event_type'] ?? $event_type)),
            'source' => $process_name,
            'log_type' => $event_type,
            'severity' => $severity,
            'computer' => $source_ip,
            'user' => $event['user'] ?? 'unknown',
            'source_ip' => $event['source_ip'] ?? '',
            'process_name' => $event['process_name'] ?? '',
            'description' => $raw_log,
            'raw' => $event_json
        ];
        
        // Evaluate against threat detection rules
        $alert = $detection_engine->evaluate_log($normalized_log);
        
        // Analyze log with rule-based analyzer
        $analysis = $analyzer->analyze($normalized_log);
        
        $response = [
            'status' => 'ok',
            'message' => 'Event stored',
            'alert' => null,
            'analysis' => $analysis
        ];
        
        // If an alert was generated, store it
        if ($alert) {
            $detection_engine->store_alert($alert);
            $response['alert'] = [
                'alert_id' => $alert['alert_id'],
                'title' => $alert['title'],
                'severity' => $alert['severity'],
                'rule_id' => $alert['rule_id']
            ];
        }
        
        http_response_code(200);
        echo json_encode($response);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to store event']);
    }
    
    $stmt->close();
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

$db->close();

?>
