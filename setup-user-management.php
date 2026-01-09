<?php
require_once 'config/config.php';
require_once 'includes/database.php';

function create_users_table() {
    $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
    $query = "CREATE TABLE IF NOT EXISTS users (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        mfa_email_enabled TINYINT(1) NOT NULL DEFAULT 0,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        status VARCHAR(50) NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );";

    if ($db->query($query)) {
        echo "'users' table created successfully or already exists.<br>";
    } else {
        echo "Error creating 'users' table: " . $db->error . "<br>";
    }

    // Add a default admin user if one doesn't exist
    $result = $db->query("SELECT user_id FROM users WHERE username = 'admin'");
    if ($result->num_rows == 0) {
        $username = 'admin';
        $password_hash = password_hash('admin', PASSWORD_DEFAULT);
        $email = 'admin@local.host';
        $role = 'admin';
        $status = 'active';
        
        $stmt = $db->prepare("INSERT INTO users (username, password_hash, email, role, status) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param('sssss', $username, $password_hash, $email, $role, $status);
        
        if ($stmt->execute()) {
            echo "Default admin user created successfully.<br>";
        } else {
            echo "Error creating default admin user: " . $stmt->error . "<br>";
        }
        $stmt->close();
    }

    // Add a default second user if one doesn't exist
    $result = $db->query("SELECT user_id FROM users WHERE username = 'user'");
    if ($result->num_rows == 0) {
        $username = 'user';
        $password_hash = password_hash('user', PASSWORD_DEFAULT);
        $email = 'user@local.host';
        $role = 'user';
        $status = 'active';

        $stmt = $db->prepare("INSERT INTO users (username, password_hash, email, role, status) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param('sssss', $username, $password_hash, $email, $role, $status);

        if ($stmt->execute()) {
            echo "Default user created successfully.<br>";
        } else {
            echo "Error creating default user: " . $stmt->error . "<br>";
        }
        $stmt->close();
    }
}

echo "<h1>User Management Setup</h1>";
create_users_table();
?>
<p>Setup complete. You can now navigate to the <a href='pages/user-management.php'>User Management</a> page.</p>
