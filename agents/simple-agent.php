<?php
/**
 * Simple PHP SIEM Agent
 * Collects Windows Event Logs and sends to SIEM collector
 * Run as: php simple-agent.php
 */

// Configuration
$SIEM_SERVER = '192.168.1.100';  // Change to your SIEM server IP
$SIEM_PORT = 9999;
$AGENT_NAME = 'PC-001';          // Change to your PC name
$COLLECTION_INTERVAL = 10;       // Seconds between collections

echo "=== JFS SIEM Simple Agent ===\n";
echo "Server: $SIEM_SERVER:$SIEM_PORT\n";
echo "Agent: $AGENT_NAME\n";
echo "Status: Running...\n\n";

// Main loop
$count = 0;
while (true) {
    try {
        // Collect Windows Event Logs
        $events = collectWindowsEvents();
        
        if (!empty($events)) {
            // Send to SIEM collector
            $sent = sendToSIEM($events);
            
            if ($sent) {
                echo "[" . date('Y-m-d H:i:s') . "] Sent " . count($events) . " events\n";
                $count += count($events);
            }
        }
        
        // Wait before next collection
        sleep($COLLECTION_INTERVAL);
        
    } catch (Exception $e) {
        echo "[ERROR] " . $e->getMessage() . "\n";
        sleep(5);
    }
}

/**
 * Collect Windows Event Logs
 */
function collectWindowsEvents() {
    $events = [];
    
    try {
        // Get Windows Event Logs using PowerShell
        $cmd = 'powershell -Command "Get-EventLog -LogName Security -Newest 10 | Select-Object -Property TimeGenerated, EventID, Message, Source | ConvertTo-Json"';
        
        $output = shell_exec($cmd);
        $logs = json_decode($output, true);
        
        if (is_array($logs)) {
            foreach ($logs as $log) {
                $events[] = [
                    'event_type' => $log['Source'] ?? 'Windows Event',
                    'severity' => getSeverity($log['EventID'] ?? 0),
                    'source_ip' => getLocalIP(),
                    'timestamp' => date('Y-m-d H:i:s', strtotime($log['TimeGenerated'] ?? 'now')),
                    'event_data' => $log['Message'] ?? '',
                    'raw_log' => json_encode($log)
                ];
            }
        }
    } catch (Exception $e) {
        // Silently fail - will retry next cycle
    }
    
    return $events;
}

/**
 * Send events to SIEM collector
 */
function sendToSIEM($events) {
    global $SIEM_SERVER, $SIEM_PORT;
    
    try {
        $socket = fsockopen($SIEM_SERVER, $SIEM_PORT, $errno, $errstr, 5);
        
        if (!$socket) {
            throw new Exception("Cannot connect to SIEM: $errstr ($errno)");
        }
        
        $data = json_encode($events);
        fwrite($socket, $data);
        
        $response = fread($socket, 1024);
        fclose($socket);
        
        return !empty($response);
        
    } catch (Exception $e) {
        echo "[ERROR] " . $e->getMessage() . "\n";
        return false;
    }
}

/**
 * Get severity based on Event ID
 */
function getSeverity($eventId) {
    // Windows Event IDs
    $critical = [4625, 4648, 4720, 4726];  // Failed login, RunAs, user create, user delete
    $high = [4688, 4697, 4698];            // Process creation, service install, scheduled task
    $medium = [4624, 4634, 4723];          // Login, logout, password change
    
    if (in_array($eventId, $critical)) {
        return 'critical';
    } elseif (in_array($eventId, $high)) {
        return 'high';
    } elseif (in_array($eventId, $medium)) {
        return 'medium';
    }
    
    return 'low';
}

/**
 * Get local IP address
 */
function getLocalIP() {
    try {
        $output = shell_exec('powershell -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notmatch \'Loopback\'} | Select-Object -First 1).IPAddress"');
        return trim($output) ?: '127.0.0.1';
    } catch (Exception $e) {
        return '127.0.0.1';
    }
}
