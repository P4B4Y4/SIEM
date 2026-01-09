<?php
/**
 * Test Agent Connection
 * Verifies that the agent can connect to the collector
 */

echo "========================================\n";
echo "Agent Connection Test\n";
echo "========================================\n\n";

// Configuration
$SIEM_SERVER = '127.0.0.1';  // Localhost for testing
$SIEM_PORT = 9999;
$AGENT_NAME = 'TEST-AGENT-001';

echo "Configuration:\n";
echo "  SIEM Server: $SIEM_SERVER\n";
echo "  SIEM Port: $SIEM_PORT\n";
echo "  Agent Name: $AGENT_NAME\n\n";

// Test 1: Check if we can connect to the collector
echo "Test 1: Checking collector connection...\n";
$socket = @fsockopen($SIEM_SERVER, $SIEM_PORT, $errno, $errstr, 5);

if ($socket) {
    echo "✓ PASS: Connected to collector at $SIEM_SERVER:$SIEM_PORT\n\n";
    
    // Test 2: Send a test event
    echo "Test 2: Sending test event...\n";
    
    $event = [
        'agent_name' => $AGENT_NAME,
        'event_type' => 'Test-Event',
        'severity' => 'medium',
        'message' => 'This is a test event from test agent',
        'timestamp' => date('Y-m-d H:i:s'),
        'source_ip' => '127.0.0.1',
        'destination_ip' => '127.0.0.1'
    ];
    
    $json_event = json_encode($event) . "\n";
    
    echo "Sending: " . json_encode($event, JSON_PRETTY_PRINT) . "\n\n";
    
    $bytes_sent = fwrite($socket, $json_event);
    
    if ($bytes_sent > 0) {
        echo "✓ PASS: Sent $bytes_sent bytes to collector\n\n";
        
        // Test 3: Check response
        echo "Test 3: Waiting for response...\n";
        $response = fgets($socket, 1024);
        
        if ($response) {
            echo "✓ PASS: Received response: $response\n";
        } else {
            echo "⚠ WARNING: No response from collector (this is normal)\n";
        }
    } else {
        echo "✗ FAIL: Could not send data to collector\n";
    }
    
    fclose($socket);
    
    echo "\n========================================\n";
    echo "Connection Test Complete!\n";
    echo "========================================\n";
    echo "\nIf test passed:\n";
    echo "1. Check dashboard: http://localhost/SIEM/pages/dashboard.php\n";
    echo "2. Should see 'Test-Event' in the events list\n";
    echo "3. Check logs: type d:\\xamp\\htdocs\\SIEM\\logs\\agent-collector.log\n";
    
} else {
    echo "✗ FAIL: Could not connect to collector\n";
    echo "Error: $errstr ($errno)\n\n";
    echo "Troubleshooting:\n";
    echo "1. Make sure Agent Collector is running\n";
    echo "2. Run: START_COLLECTORS.bat\n";
    echo "3. Verify port 9999 is listening\n";
    echo "4. Check firewall settings\n";
}

?>
