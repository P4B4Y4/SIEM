<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/settings.php';

$interval_seconds = 60;
$limit = 200;
$token = (string)getSetting('email_notifications.cron_token', '');

$lock_file = __DIR__ . '/../logs/email_sender_worker.lock';
$lock_fp = fopen($lock_file, 'c');
if (!$lock_fp) {
    fwrite(STDERR, "Unable to open lock file: {$lock_file}\n");
    exit(1);
}
if (!flock($lock_fp, LOCK_EX | LOCK_NB)) {
    // Another instance is running
    exit(0);
}

$log_file = __DIR__ . '/../logs/email_sender_worker.log';
function log_line($msg) {
    global $log_file;
    @error_log('[' . date('Y-m-d H:i:s') . '] ' . $msg . "\n", 3, $log_file);
}

$base_url = (string)getSetting('email_notifications.local_url', 'http://localhost/SIEM');
$base_url = rtrim($base_url, '/');

$endpoint = $base_url . '/api/send-alert-email.php?action=send_pending&limit=' . urlencode((string)$limit);
if ($token !== '') {
    $endpoint .= '&token=' . urlencode($token);
}

log_line('worker_start endpoint=' . $endpoint);

while (true) {
    $ch = curl_init($endpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 55);

    $resp = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($resp === false) {
        log_line('request_failed curl_error=' . $err);
    } else {
        log_line('request_done http=' . $http . ' resp=' . substr((string)$resp, 0, 400));
    }

    sleep($interval_seconds);
}
