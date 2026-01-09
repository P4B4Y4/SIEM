<?php
/**
 * JFS SIEM - Get Connected Agents
 * Returns list of agents from actual event data sent to the collector
 */

header('Content-Type: application/json');

$agents = [];

// Try MySQL first (primary database)
try {
    $db = new mysqli('localhost', 'root', '', 'jfs_siem');
    
    if (!$db->connect_error) {
        // Get unique agents from security_events table
        $result = $db->query("
            SELECT DISTINCT 
                agent_id as id,
                agent_id as name,
                source_ip as ip,
                agent_id as hostname,
                'online' as status,
                MAX(timestamp) as last_seen
            FROM security_events
            WHERE agent_id IS NOT NULL AND agent_id != ''
            GROUP BY agent_id
            ORDER BY last_seen DESC
            LIMIT 50
        ");
        
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $agents[] = $row;
            }
        }
        $db->close();
    }
} catch (Exception $e) {
    // MySQL failed, try SQLite
}

// If no agents from MySQL, try SQLite
if (empty($agents)) {
    try {
        $db_file = __DIR__ . '/../data/siem.db';
        
        if (file_exists($db_file)) {
            $db = new PDO('sqlite:' . $db_file);
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Try to get agents from events table if it exists
            $stmt = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='events'");
            if ($stmt->fetch()) {
                $stmt = $db->prepare("
                    SELECT DISTINCT 
                        agent as id,
                        agent as name,
                        '127.0.0.1' as ip,
                        agent as hostname,
                        'online' as status,
                        MAX(timestamp) as last_seen
                    FROM events
                    WHERE agent IS NOT NULL AND agent != ''
                    GROUP BY agent
                    ORDER BY last_seen DESC
                ");
                $stmt->execute();
                $agents = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }
            
            // If still no agents, try agents table
            if (empty($agents)) {
                $stmt = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='agents'");
                if ($stmt->fetch()) {
                    $stmt = $db->prepare("SELECT id, name, ip, hostname, status, last_seen FROM agents ORDER BY last_seen DESC");
                    $stmt->execute();
                    $agents = $stmt->fetchAll(PDO::FETCH_ASSOC);
                }
            }
        }
    } catch (Exception $e) {
        // Both databases failed
    }
}

echo json_encode([
    'success' => true,
    'agents' => $agents,
    'count' => count($agents),
    'source' => empty($agents) ? 'no_data' : 'database'
]);
?>
