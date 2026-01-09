<?php
/**
 * Clear pending commands from database
 * Use this to clean up stuck commands
 */

$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

echo "<h2>Pending Commands Cleanup</h2>";

// Get count before
$before = $db->query("SELECT COUNT(*) as count FROM remote_commands WHERE status = 'pending'");
$before_row = $before->fetch_assoc();
$before_count = $before_row['count'];

echo "<p><strong>Before:</strong> $before_count pending commands</p>";

// Option 1: Clear ALL pending commands (recommended)
$clear_all = isset($_GET['clear_all']) ? true : false;

if ($clear_all) {
    // Clear ALL pending commands
    $result = $db->query("DELETE FROM remote_commands WHERE status = 'pending'");
    $deleted = $db->affected_rows;
    
    echo "<p style='color: green;'><strong>✓ Deleted all $deleted pending commands</strong></p>";
} else {
    // Clear only screenshot commands
    $result = $db->query("DELETE FROM remote_commands WHERE status = 'pending' AND command = 'screenshot'");
    $deleted = $db->affected_rows;
    
    echo "<p style='color: green;'><strong>✓ Deleted $deleted screenshot commands</strong></p>";
}

// Get count after
$after = $db->query("SELECT COUNT(*) as count FROM remote_commands WHERE status = 'pending'");
$after_row = $after->fetch_assoc();
$after_count = $after_row['count'];

echo "<p><strong>After:</strong> $after_count pending commands</p>";

if (!$clear_all) {
    echo "<p style='color: orange;'><strong>⚠ Still have $after_count pending commands</strong></p>";
    echo "<p><a href='?clear_all=1' style='color: red; font-weight: bold;'>Click here to clear ALL pending commands</a></p>";
}

echo "<p><a href='pages/remote-terminal.php'>Go to Remote Terminal</a></p>";

$db->close();
?>
