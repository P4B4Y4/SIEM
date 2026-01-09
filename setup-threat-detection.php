<?php
/**
 * Setup script for Threat Detection Engine
 * Creates necessary database tables for alert storage
 */

session_start();
require_once 'config/config.php';
require_once 'includes/database.php';
require_once 'includes/auth.php';

// Check authentication
if (!isset($_SESSION['user_id'])) {
    header('Location: pages/login.php');
    exit;
}

// Get database connection
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

$message = '';
$message_type = '';

// Create tables if requested
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['setup'])) {
    // Create security_alerts table
    $sql = "CREATE TABLE IF NOT EXISTS security_alerts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        alert_id VARCHAR(50) UNIQUE NOT NULL,
        title VARCHAR(255) NOT NULL,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
        rule_id VARCHAR(100) NOT NULL,
        matched_event_id VARCHAR(50),
        timestamp DATETIME NOT NULL,
        category VARCHAR(100),
        description TEXT,
        details JSON,
        recommended_actions JSON,
        raw_log JSON,
        status ENUM('new', 'acknowledged', 'resolved') DEFAULT 'new',
        assigned_to VARCHAR(100),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_severity (severity),
        INDEX idx_timestamp (timestamp),
        INDEX idx_status (status),
        INDEX idx_rule_id (rule_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    
    if ($db->query($sql)) {
        $message = '✓ security_alerts table created successfully';
        $message_type = 'success';
    } else {
        $message = '✗ Error creating security_alerts table: ' . $db->error;
        $message_type = 'error';
    }
    
    // Create alert_rules table
    $sql = "CREATE TABLE IF NOT EXISTS alert_rules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        rule_id VARCHAR(100) UNIQUE NOT NULL,
        title VARCHAR(255) NOT NULL,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
        category VARCHAR(100),
        description TEXT,
        event_ids JSON,
        conditions JSON,
        enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_rule_id (rule_id),
        INDEX idx_severity (severity)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    
    if ($db->query($sql)) {
        $message .= '<br>✓ alert_rules table created successfully';
    } else {
        $message .= '<br>✗ Error creating alert_rules table: ' . $db->error;
        $message_type = 'error';
    }
    
    // Create alert_history table
    $sql = "CREATE TABLE IF NOT EXISTS alert_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        alert_id VARCHAR(50) NOT NULL,
        action VARCHAR(50),
        user VARCHAR(100),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        FOREIGN KEY (alert_id) REFERENCES security_alerts(alert_id),
        INDEX idx_alert_id (alert_id),
        INDEX idx_timestamp (timestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    
    if ($db->query($sql)) {
        $message .= '<br>✓ alert_history table created successfully';
    } else {
        $message .= '<br>✗ Error creating alert_history table: ' . $db->error;
        $message_type = 'error';
    }
}

// Check if tables exist
$tables_exist = true;
$missing_tables = [];

$tables = ['security_alerts', 'alert_rules', 'alert_history'];
foreach ($tables as $table) {
    $result = $db->query("SHOW TABLES LIKE '$table'");
    if ($result->num_rows === 0) {
        $tables_exist = false;
        $missing_tables[] = $table;
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Detection Setup - JFS SIEM</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            max-width: 600px;
            width: 100%;
            padding: 40px;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        .subtitle {
            color: #999;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .status-section {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            padding: 10px 0;
            font-size: 14px;
        }
        
        .status-icon {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 10px;
            color: white;
            font-size: 12px;
        }
        
        .status-icon.exists {
            background: #10b981;
        }
        
        .status-icon.missing {
            background: #ef4444;
        }
        
        .table-list {
            margin-top: 15px;
        }
        
        .table-item {
            padding: 8px 0;
            font-size: 13px;
            color: #666;
        }
        
        .table-item i {
            margin-right: 8px;
            width: 20px;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 5px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
            width: 100%;
        }
        
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn-primary:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        
        .features {
            margin-top: 30px;
            padding-top: 30px;
            border-top: 1px solid #eee;
        }
        
        .features h3 {
            color: #333;
            font-size: 16px;
            margin-bottom: 15px;
        }
        
        .feature-list {
            list-style: none;
        }
        
        .feature-list li {
            padding: 8px 0;
            color: #666;
            font-size: 13px;
        }
        
        .feature-list li:before {
            content: "✓ ";
            color: #10b981;
            font-weight: bold;
            margin-right: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1><i class="fas fa-shield-alt"></i> Threat Detection Engine</h1>
        <p class="subtitle">Setup database tables for security alert storage</p>
        
        <?php if ($message): ?>
            <div class="message <?php echo $message_type; ?>">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>
        
        <div class="status-section">
            <h3 style="margin-bottom: 15px; color: #333; font-size: 14px;">Database Tables Status</h3>
            
            <div class="status-item">
                <div class="status-icon <?php echo in_array('security_alerts', $missing_tables) ? 'missing' : 'exists'; ?>">
                    <?php echo in_array('security_alerts', $missing_tables) ? '✗' : '✓'; ?>
                </div>
                <span>security_alerts</span>
            </div>
            
            <div class="status-item">
                <div class="status-icon <?php echo in_array('alert_rules', $missing_tables) ? 'missing' : 'exists'; ?>">
                    <?php echo in_array('alert_rules', $missing_tables) ? '✗' : '✓'; ?>
                </div>
                <span>alert_rules</span>
            </div>
            
            <div class="status-item">
                <div class="status-icon <?php echo in_array('alert_history', $missing_tables) ? 'missing' : 'exists'; ?>">
                    <?php echo in_array('alert_history', $missing_tables) ? '✗' : '✓'; ?>
                </div>
                <span>alert_history</span>
            </div>
        </div>
        
        <?php if (!$tables_exist): ?>
            <form method="POST">
                <button type="submit" name="setup" class="btn btn-primary">
                    <i class="fas fa-database"></i> Create Database Tables
                </button>
            </form>
        <?php else: ?>
            <div style="background: #d4edda; padding: 15px; border-radius: 5px; text-align: center; color: #155724; font-size: 14px;">
                <i class="fas fa-check-circle"></i> All tables are ready!
            </div>
        <?php endif; ?>
        
        <div class="features">
            <h3><i class="fas fa-cog"></i> Detection Capabilities</h3>
            <ul class="feature-list">
                <li>Critical event detection (log tampering, service installation, crashes)</li>
                <li>Brute-force attack detection (10+ failures in 5 minutes)</li>
                <li>Suspicious process execution (cmd.exe, PowerShell)</li>
                <li>Privilege escalation detection</li>
                <li>Repeated crash correlation</li>
                <li>Account management monitoring</li>
                <li>Structured alert generation with recommendations</li>
                <li>Alert severity classification (Low, Medium, High, Critical)</li>
                <li>Alert history and audit trail</li>
                <li>Rule-based static detection (no AI required)</li>
            </ul>
        </div>
    </div>
</body>
</html>
