<?php
/**
 * Migrate remote_commands table to add output and error columns
 */

$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

echo "<h2>Remote Commands Table Migration</h2>";

try {
    // Check if table exists
    $table_check = $db->query("SHOW TABLES LIKE 'remote_commands'");
    
    if ($table_check->num_rows == 0) {
        echo "<p style='color: red;'><strong>✗ Table 'remote_commands' does not exist!</strong></p>";
        echo "<p>Creating table...</p>";
        
        $create_sql = "
            CREATE TABLE remote_commands (
                id INT AUTO_INCREMENT PRIMARY KEY,
                agent_name VARCHAR(255),
                command LONGTEXT,
                status VARCHAR(50),
                result VARCHAR(50),
                output LONGTEXT,
                error LONGTEXT,
                timestamp DATETIME,
                completed_at DATETIME,
                INDEX(agent_name),
                INDEX(status)
            )
        ";
        
        if ($db->query($create_sql)) {
            echo "<p style='color: green;'><strong>✓ Created remote_commands table</strong></p>";
        } else {
            echo "<p style='color: red;'><strong>✗ Error creating table: " . $db->error . "</strong></p>";
        }
    } else {
        echo "<p><strong>Table exists, checking columns...</strong></p>";
        
        // Check if columns exist
        $result = $db->query("SHOW COLUMNS FROM remote_commands LIKE 'output'");
        
        if ($result->num_rows == 0) {
            // Add output column
            if ($db->query("ALTER TABLE remote_commands ADD COLUMN output LONGTEXT DEFAULT NULL")) {
                echo "<p style='color: green;'>✓ Added output column</p>";
            } else {
                echo "<p style='color: red;'>✗ Error adding output column: " . $db->error . "</p>";
            }
        } else {
            echo "<p>✓ output column already exists</p>";
        }
        
        $result = $db->query("SHOW COLUMNS FROM remote_commands LIKE 'error'");
        
        if ($result->num_rows == 0) {
            // Add error column
            if ($db->query("ALTER TABLE remote_commands ADD COLUMN error LONGTEXT DEFAULT NULL")) {
                echo "<p style='color: green;'>✓ Added error column</p>";
            } else {
                echo "<p style='color: red;'>✗ Error adding error column: " . $db->error . "</p>";
            }
        } else {
            echo "<p>✓ error column already exists</p>";
        }
        
        $result = $db->query("SHOW COLUMNS FROM remote_commands LIKE 'completed_at'");
        
        if ($result->num_rows == 0) {
            // Add completed_at column
            if ($db->query("ALTER TABLE remote_commands ADD COLUMN completed_at DATETIME DEFAULT NULL")) {
                echo "<p style='color: green;'>✓ Added completed_at column</p>";
            } else {
                echo "<p style='color: red;'>✗ Error adding completed_at column: " . $db->error . "</p>";
            }
        } else {
            echo "<p>✓ completed_at column already exists</p>";
        }
    }
    
    echo "<br><p style='color: green;'><strong>✓ Migration complete!</strong></p>";
    
    // Show table structure
    echo "<p><strong>Current table structure:</strong></p>";
    echo "<pre>";
    $result = $db->query("DESCRIBE remote_commands");
    while ($row = $result->fetch_assoc()) {
        echo $row['Field'] . " (" . $row['Type'] . ")\n";
    }
    echo "</pre>";
    
} catch (Exception $e) {
    echo "<p style='color: red;'><strong>Error: " . $e->getMessage() . "</strong></p>";
}

$db->close();
?>
