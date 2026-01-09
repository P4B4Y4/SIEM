<?php
/**
 * Events Helper Module
 * Functions for event management and filtering
 */

/**
 * Get events with filters
 */
function getEvents($filters = [], $limit = 20, $offset = 0) {
    $db = getDatabase();
    
    $where = "WHERE 1=1";
    
    if (!empty($filters['severity'])) {
        $where .= " AND severity = '" . $db->escape($filters['severity']) . "'";
    }
    
    if (!empty($filters['event_type'])) {
        $where .= " AND event_type LIKE '%" . $db->escape($filters['event_type']) . "%'";
    }
    
    if (!empty($filters['source_ip'])) {
        $where .= " AND source_ip = '" . $db->escape($filters['source_ip']) . "'";
    }
    
    if (!empty($filters['search'])) {
        $search = $db->escape($filters['search']);
        $where .= " AND (event_type LIKE '%$search%' OR source_ip LIKE '%$search%' OR dest_ip LIKE '%$search%')";
    }
    
    $result = $db->query("
        SELECT * FROM security_events 
        $where
        ORDER BY timestamp DESC 
        LIMIT $limit OFFSET $offset
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get event count with filters
 */
function getEventCount($filters = []) {
    $db = getDatabase();
    
    $where = "WHERE 1=1";
    
    if (!empty($filters['severity'])) {
        $where .= " AND severity = '" . $db->escape($filters['severity']) . "'";
    }
    
    if (!empty($filters['event_type'])) {
        $where .= " AND event_type LIKE '%" . $db->escape($filters['event_type']) . "%'";
    }
    
    if (!empty($filters['source_ip'])) {
        $where .= " AND source_ip = '" . $db->escape($filters['source_ip']) . "'";
    }
    
    $result = $db->query("SELECT COUNT(*) as total FROM security_events $where");
    
    return $result ? $result->fetch_assoc()['total'] : 0;
}

/**
 * Get event by ID
 */
function getEventById($event_id) {
    $db = getDatabase();
    $event_id = (int)$event_id;
    
    $result = $db->query("SELECT * FROM security_events WHERE event_id = $event_id");
    
    return $result ? $result->fetch_assoc() : null;
}

/**
 * Get event statistics
 */
function getEventStats() {
    $db = getDatabase();
    
    $stats = [
        'total' => 0,
        'critical' => 0,
        'high' => 0,
        'medium' => 0,
        'low' => 0,
        'info' => 0
    ];
    
    // Get total
    $result = $db->query("SELECT COUNT(*) as total FROM security_events");
    if ($result) {
        $stats['total'] = $result->fetch_assoc()['total'];
    }
    
    // Get by severity
    $result = $db->query("
        SELECT severity, COUNT(*) as count 
        FROM security_events 
        GROUP BY severity
    ");
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $severity = strtolower($row['severity']);
            if (isset($stats[$severity])) {
                $stats[$severity] = $row['count'];
            }
        }
    }
    
    return $stats;
}

/**
 * Get events by severity
 */
function getEventsBySeverity($severity, $limit = 10) {
    $db = getDatabase();
    $severity = $db->escape($severity);
    
    $result = $db->query("
        SELECT * FROM security_events 
        WHERE severity = '$severity'
        ORDER BY timestamp DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get critical events
 */
function getCriticalEvents($limit = 5) {
    return getEventsBySeverity('critical', $limit);
}

/**
 * Get high severity events
 */
function getHighEvents($limit = 5) {
    return getEventsBySeverity('high', $limit);
}

/**
 * Get events by type
 */
function getEventsByType($event_type, $limit = 10) {
    $db = getDatabase();
    $event_type = $db->escape($event_type);
    
    $result = $db->query("
        SELECT * FROM security_events 
        WHERE event_type = '$event_type'
        ORDER BY timestamp DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get events from source IP
 */
function getEventsBySourceIP($source_ip, $limit = 10) {
    $db = getDatabase();
    $source_ip = $db->escape($source_ip);
    
    $result = $db->query("
        SELECT * FROM security_events 
        WHERE source_ip = '$source_ip'
        ORDER BY timestamp DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get events from destination IP
 */
function getEventsByDestinationIP($dest_ip, $limit = 10) {
    $db = getDatabase();
    $dest_ip = $db->escape($dest_ip);
    
    $result = $db->query("
        SELECT * FROM security_events 
        WHERE dest_ip = '$dest_ip'
        ORDER BY timestamp DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get events in date range
 */
function getEventsByDateRange($start_date, $end_date, $limit = 100) {
    $db = getDatabase();
    $start_date = $db->escape($start_date);
    $end_date = $db->escape($end_date);
    
    $result = $db->query("
        SELECT * FROM security_events 
        WHERE timestamp BETWEEN '$start_date' AND '$end_date'
        ORDER BY timestamp DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get top event types
 */
function getTopEventTypes($limit = 10) {
    $db = getDatabase();
    
    $result = $db->query("
        SELECT event_type, COUNT(*) as count 
        FROM security_events 
        GROUP BY event_type 
        ORDER BY count DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get top source IPs
 */
function getTopSourceIPs($limit = 10) {
    $db = getDatabase();
    
    $result = $db->query("
        SELECT source_ip, COUNT(*) as count 
        FROM security_events 
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Get top destination IPs
 */
function getTopDestinationIPs($limit = 10) {
    $db = getDatabase();
    
    $result = $db->query("
        SELECT dest_ip, COUNT(*) as count 
        FROM security_events 
        WHERE dest_ip IS NOT NULL
        GROUP BY dest_ip 
        ORDER BY count DESC 
        LIMIT $limit
    ");
    
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

/**
 * Format event for display
 */
function formatEvent($event) {
    return [
        'id' => $event['event_id'],
        'timestamp' => date('M d, Y H:i:s', strtotime($event['timestamp'])),
        'type' => escape($event['event_type'] ?? 'Unknown'),
        'severity' => ucfirst($event['severity'] ?? 'Info'),
        'source_ip' => escape($event['source_ip'] ?? '-'),
        'dest_ip' => escape($event['dest_ip'] ?? '-'),
        'protocol' => escape($event['protocol'] ?? '-'),
        'raw' => $event
    ];
}
