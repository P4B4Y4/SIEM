<?php
require_once 'config/config.php';
require_once 'includes/database.php';

function ensure_users_mfa_column($db) {
    $col = $db->query("SHOW COLUMNS FROM users LIKE 'mfa_email_enabled'");
    if ($col && $col->num_rows === 0) {
        if ($db->query("ALTER TABLE users ADD COLUMN mfa_email_enabled TINYINT(1) NOT NULL DEFAULT 0")) {
            echo "Added users.mfa_email_enabled column.<br>";
        } else {
            echo "Error adding users.mfa_email_enabled column: " . $db->error . "<br>";
        }
    } else {
        echo "users.mfa_email_enabled column already exists.<br>";
    }
}

function create_user_mfa_email_otps_table($db) {
    $query = "CREATE TABLE IF NOT EXISTS user_mfa_email_otps (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        otp_hash VARCHAR(255) NOT NULL,
        expires_at DATETIME NOT NULL,
        attempts INT NOT NULL DEFAULT 0,
        last_sent_at DATETIME NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id),
        INDEX idx_expires_at (expires_at),
        CONSTRAINT fk_user_mfa_email_otps_user_id FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    if ($db->query($query)) {
        echo "user_mfa_email_otps table created successfully or already exists.<br>";
    } else {
        echo "Error creating user_mfa_email_otps table: " . $db->error . "<br>";
    }
}

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    echo "DB connection error: " . $db->connect_error;
    exit;
}

echo "<h1>Email MFA Setup</h1>";
ensure_users_mfa_column($db);
create_user_mfa_email_otps_table($db);

$db->close();
?>
<p>Setup complete. Next: enable MFA per user in user management and test login.</p>
