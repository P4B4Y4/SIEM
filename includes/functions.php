<?php
/**
 * Helper Functions
 * Common utility functions for the application
 */

/**
 * Sanitize user input
 */
function sanitize($input) {
    $db = getDatabase();
    return htmlspecialchars($db->escape($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Escape HTML output
 */
function escape($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/**
 * Format bytes to human readable
 */
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, $precision) . ' ' . $units[$pow];
}

/**
 * Get time ago string
 */
function timeAgo($timestamp) {
    $now = time();
    $diff = $now - strtotime($timestamp);

    if ($diff < 60) {
        return 'just now';
    } elseif ($diff < 3600) {
        $mins = floor($diff / 60);
        return $mins . ' minute' . ($mins > 1 ? 's' : '') . ' ago';
    } elseif ($diff < 86400) {
        $hours = floor($diff / 3600);
        return $hours . ' hour' . ($hours > 1 ? 's' : '') . ' ago';
    } elseif ($diff < 604800) {
        $days = floor($diff / 86400);
        return $days . ' day' . ($days > 1 ? 's' : '') . ' ago';
    } else {
        return date('M d, Y', strtotime($timestamp));
    }
}

/**
 * Redirect to URL
 */
function redirect($url) {
    header('Location: ' . $url);
    exit();
}

/**
 * Get dashboard statistics
 */
function getDashboardStats() {
    $db = getDatabase();
    $stats = [];

    // Total events
    $result = $db->query("SELECT COUNT(*) as count FROM security_events");
    $stats['total_events'] = $result ? $result->fetch_assoc()['count'] : 0;

    // Critical alerts (lowercase)
    $result = $db->query("SELECT COUNT(*) as count FROM security_events WHERE severity = 'critical'");
    $stats['critical_alerts'] = $result ? $result->fetch_assoc()['count'] : 0;

    // High alerts (lowercase)
    $result = $db->query("SELECT COUNT(*) as count FROM security_events WHERE severity = 'high'");
    $stats['high_alerts'] = $result ? $result->fetch_assoc()['count'] : 0;

    // Active agents (check if table exists)
    $tables = $db->query("SHOW TABLES LIKE 'agents'");
    if ($tables && $tables->num_rows > 0) {
        $result = $db->query("SELECT COUNT(*) as count FROM agents WHERE status = 'active'");
        $stats['active_agents'] = $result ? $result->fetch_assoc()['count'] : 0;
    } else {
        $stats['active_agents'] = 0;
    }

    return $stats;
}

/**
 * Get recent events
 */
function getRecentEvents($limit = 10) {
    $db = getDatabase();
    $limit = (int)$limit;
    
    $result = $db->query("
        SELECT event_id, event_type, severity, source_ip, dest_ip, source_port, dest_port, 
               raw_log, timestamp, agent_id, processed, threat_intel_match
        FROM security_events 
        ORDER BY event_id DESC 
        LIMIT $limit
    ");

    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Log message to file
 */
function logMessage($level, $message) {
    $logFile = LOG_DIR . strtolower($level) . '.log';
    $timestamp = date('Y-m-d H:i:s');
    $message = "[$timestamp] [$level] $message\n";
    error_log($message, 3, $logFile);
}

/**
 * Check if directory is writable
 */
function isDirectoryWritable($dir) {
    return is_dir($dir) && is_writable($dir);
}

/**
 * Create directory if not exists
 */
function ensureDirectory($dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    return is_dir($dir);
}
