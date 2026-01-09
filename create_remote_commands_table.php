<?php
/**
 * Create remote_commands table for remote access functionality
 */

$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

// Create remote_commands table
$sql = "CREATE TABLE IF NOT EXISTS remote_commands (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_name VARCHAR(255) NOT NULL,
    command TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',
    result TEXT,
    INDEX idx_agent_status (agent_name, status),
    INDEX idx_timestamp (timestamp)
)";

if ($db->query($sql) === TRUE) {
    echo "✓ remote_commands table created successfully!<br>";
} else {
    echo "✗ Error creating table: " . $db->error . "<br>";
}

// Check if table exists
$result = $db->query("SHOW TABLES LIKE 'remote_commands'");
if ($result->num_rows > 0) {
    echo "✓ Table verified!<br>";
    
    // Show table structure
    $result = $db->query("DESCRIBE remote_commands");
    echo "<br>Table Structure:<br>";
    echo "<pre>";
    while ($row = $result->fetch_assoc()) {
        echo $row['Field'] . " - " . $row['Type'] . "\n";
    }
    echo "</pre>";
} else {
    echo "✗ Table does not exist!<br>";
}

$db->close();
?>
