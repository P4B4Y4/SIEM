<?php
/**
 * Test Listeners - Send test syslog messages
 */

echo "=== Testing Syslog Listeners ===\n\n";

// Test Fortinet listener (port 514)
echo "1. Testing Fortinet Listener (Port 514)...\n";
$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
$test_msg = "<134>Dec 09 16:20:00 FortiGate test: srcip=192.168.1.50 dstip=8.8.8.8 action=deny";
$result = socket_sendto($sock, $test_msg, strlen($test_msg), 0, "127.0.0.1", 514);
socket_close($sock);

if ($result !== false) {
    echo "   ✓ Test message sent to port 514\n";
} else {
    echo "   ✗ Failed to send to port 514\n";
}

// Test ESET listener (port 6514)
echo "\n2. Testing ESET Listener (Port 6514)...\n";
$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
$test_msg = "<134>Dec 09 16:20:00 ESET test: virus detected - Trojan.Win32.Generic";
$result = socket_sendto($sock, $test_msg, strlen($test_msg), 0, "127.0.0.1", 6514);
socket_close($sock);

if ($result !== false) {
    echo "   ✓ Test message sent to port 6514\n";
} else {
    echo "   ✗ Failed to send to port 6514\n";
}

// Check database
echo "\n3. Checking Database for Events...\n";
try {
    $db = new mysqli('localhost', 'root', '', 'jfs_siem');
    
    if ($db->connect_error) {
        echo "   ✗ Database connection failed\n";
    } else {
        $result = $db->query("SELECT COUNT(*) as total FROM security_events");
        $row = $result->fetch_assoc();
        echo "   ✓ Total events in database: " . $row['total'] . "\n";
        
        // Show recent events
        $recent = $db->query("SELECT event_id, event_type, severity, timestamp FROM security_events ORDER BY event_id DESC LIMIT 5");
        echo "\n   Recent Events:\n";
        while ($event = $recent->fetch_assoc()) {
            echo "   - ID: {$event['event_id']}, Type: {$event['event_type']}, Severity: {$event['severity']}, Time: {$event['timestamp']}\n";
        }
    }
} catch (Exception $e) {
    echo "   ✗ Error: " . $e->getMessage() . "\n";
}

echo "\n=== Test Complete ===\n";

?>
