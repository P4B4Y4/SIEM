<?php
/**
 * Test the report_command API
 */

$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

echo "<h2>Test Report Command API</h2>";

// Test 1: Get a pending command
$result = $db->query("SELECT id FROM remote_commands WHERE status = 'pending' LIMIT 1");
$row = $result->fetch_assoc();

if (!$row) {
    echo "<p style='color: red;'>No pending commands found. Send a command first.</p>";
    $db->close();
    exit;
}

$cmd_id = $row['id'];
echo "<p><strong>Testing with command ID:</strong> $cmd_id</p>";

// Test 2: Simulate the report_command call
$status = 'success';
$result_val = 'success';
$output = 'Test output';
$error = '';

$stmt = $db->prepare("
    UPDATE remote_commands
    SET status = ?, result = ?, output = ?, error = ?, completed_at = NOW()
    WHERE id = ?
");

if (!$stmt) {
    echo "<p style='color: red;'><strong>Error preparing statement:</strong> " . $db->error . "</p>";
    $db->close();
    exit;
}

$stmt->bind_param("ssssi", $status, $result_val, $output, $error, $cmd_id);

if ($stmt->execute()) {
    echo "<p style='color: green;'><strong>✓ Update successful!</strong></p>";
    echo "<p>Affected rows: " . $stmt->affected_rows . "</p>";
    
    // Verify the update
    $verify = $db->query("SELECT id, command, status FROM remote_commands WHERE id = $cmd_id");
    $verify_row = $verify->fetch_assoc();
    
    echo "<p><strong>Verification:</strong></p>";
    echo "<pre>";
    print_r($verify_row);
    echo "</pre>";
} else {
    echo "<p style='color: red;'><strong>Error executing statement:</strong> " . $stmt->error . "</p>";
}

$stmt->close();
$db->close();
?>
