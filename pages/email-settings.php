<?php
session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';

// Check authentication
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user = ['username' => $_SESSION['username'] ?? 'Admin', 'role' => 'user'];

// Load email settings from file or database
$settings_file = '../config/email_settings.json';
$email_settings = [];

if (file_exists($settings_file)) {
    $email_settings = json_decode(file_get_contents($settings_file), true);
}

// Set defaults
$email_settings = array_merge([
    'smtp_host' => 'localhost',
    'smtp_port' => 587,
    'smtp_user' => '',
    'smtp_pass' => '',
    'from_email' => 'siem@localhost',
    'from_name' => 'SIEM Alert System',
    'use_smtp' => false,
    'enable_notifications' => false,
    'critical_recipients' => '',
    'warning_recipients' => '',
    'info_recipients' => ''
], $email_settings);

// Handle form submission
$message = '';
$message_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'save_settings') {
        $email_settings = [
            'smtp_host' => $_POST['smtp_host'] ?? 'localhost',
            'smtp_port' => (int)($_POST['smtp_port'] ?? 587),
            'smtp_user' => $_POST['smtp_user'] ?? '',
            'smtp_pass' => $_POST['smtp_pass'] ?? '',
            'from_email' => $_POST['from_email'] ?? 'siem@localhost',
            'from_name' => $_POST['from_name'] ?? 'SIEM Alert System',
            'use_smtp' => isset($_POST['use_smtp']) ? true : false,
            'enable_notifications' => isset($_POST['enable_notifications']) ? true : false,
            'critical_recipients' => $_POST['critical_recipients'] ?? '',
            'warning_recipients' => $_POST['warning_recipients'] ?? '',
            'info_recipients' => $_POST['info_recipients'] ?? ''
        ];
        
        // Save to file
        if (file_put_contents($settings_file, json_encode($email_settings, JSON_PRETTY_PRINT))) {
            $message = 'Email settings saved successfully!';
            $message_type = 'success';
        } else {
            $message = 'Failed to save email settings';
            $message_type = 'error';
        }
    } elseif ($_POST['action'] === 'test_connection') {
        // Test SMTP connection
        $test_result = test_smtp_connection(
            $_POST['smtp_host'] ?? 'localhost',
            (int)($_POST['smtp_port'] ?? 587)
        );
        
        if ($test_result['success']) {
            $message = 'SMTP connection successful!';
            $message_type = 'success';
        } else {
            $message = 'SMTP connection failed: ' . $test_result['error'];
            $message_type = 'error';
        }
    } elseif ($_POST['action'] === 'send_test_email') {
        // Send test email
        $test_email = $_POST['test_email'] ?? '';
        
        if (empty($test_email)) {
            $message = 'Please enter a test email address';
            $message_type = 'error';
        } else {
            $result = send_test_email($test_email, $email_settings);
            
            if ($result['success']) {
                $message = 'Test email sent successfully to ' . htmlspecialchars($test_email);
                $message_type = 'success';
            } else {
                $message = 'Failed to send test email: ' . $result['error'];
                $message_type = 'error';
            }
        }
    }
}

// Test SMTP connection function
function test_smtp_connection($host, $port) {
    $timeout = 5;
    $errno = 0;
    $errstr = '';
    
    $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
    
    if (!$socket) {
        return [
            'success' => false,
            'error' => "Connection failed: $errstr ($errno)"
        ];
    }
    
    fclose($socket);
    
    return [
        'success' => true,
        'message' => 'Connection successful'
    ];
}

// Send test email function
function send_test_email($recipient, $settings) {
    require_once '../includes/alert_notifier.php';
    
    $notifier = new AlertNotifier([
        'host' => $settings['smtp_host'],
        'port' => $settings['smtp_port'],
        'user' => $settings['smtp_user'],
        'pass' => $settings['smtp_pass'],
        'from_email' => $settings['from_email'],
        'from_name' => $settings['from_name'],
        'use_smtp' => $settings['use_smtp']
    ]);
    
    $test_alert = [
        'alert_id' => 'TEST_ALERT_001',
        'title' => 'Test Alert - Email Configuration Verification',
        'alert_level' => 'Informational',
        'timestamp' => date('Y-m-d H:i:s'),
        'computer' => 'TEST-SYSTEM',
        'source' => 'Email Settings',
        'category' => 'System',
        'severity' => 'low',
        'anomaly' => 'No',
        'reason' => 'This is a test email to verify SMTP configuration',
        'recommendation' => 'If you received this email, your SMTP settings are configured correctly.',
        'escalation' => 'Review in normal shift'
    ];
    
    $result = $notifier->send_alert_email($test_alert, $recipient);
    
    if ($result) {
        return ['success' => true];
    } else {
        return ['success' => false, 'error' => $notifier->get_last_error() ?: 'Failed to send email'];
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Settings - <?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        
        .navbar {
            background: white;
            padding: 15px 30px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .navbar-brand {
            font-size: 20px;
            font-weight: 600;
            color: #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .navbar-menu {
            display: flex;
            gap: 30px;
        }
        
        .navbar-menu a {
            text-decoration: none;
            color: #666;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: color 0.3s;
        }
        
        .navbar-menu a:hover,
        .navbar-menu a.active {
            color: #667eea;
        }
        
        .user-menu {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .btn-logout {
            background: #ef4444;
            color: white;
            padding: 8px 16px;
            border-radius: 5px;
            text-decoration: none;
            font-size: 13px;
            transition: background 0.3s;
        }
        
        .btn-logout:hover {
            background: #dc2626;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 30px;
        }
        
        .page-title {
            font-size: 32px;
            margin-bottom: 30px;
            color: #333;
        }
        
        .message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .message.success {
            background: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        
        .message.error {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        
        .card-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #666;
            font-size: 14px;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            font-family: inherit;
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 80px;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
            margin: 0;
        }
        
        .checkbox-group label {
            margin: 0;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
        }
        
        .btn-secondary {
            background: #f0f0f0;
            color: #333;
        }
        
        .btn-secondary:hover {
            background: #e0e0e0;
        }
        
        .btn-success {
            background: #10b981;
            color: white;
        }
        
        .btn-success:hover {
            background: #059669;
        }
        
        .hint {
            font-size: 12px;
            color: #999;
            margin-top: 5px;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-indicator.enabled {
            background: #10b981;
        }
        
        .status-indicator.disabled {
            background: #ef4444;
        }
        
        .section {
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #333;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .button-group {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar">
        <div class="navbar-brand">
            <i class="fas fa-envelope"></i>
            <span><?php echo APP_NAME; ?></span>
        </div>
        <div class="navbar-menu">
            <a href="dashboard.php"><i class="fas fa-home"></i> Dashboard</a>
            <a href="events.php"><i class="fas fa-list"></i> Events</a>
            <a href="threats.php"><i class="fas fa-exclamation-triangle"></i> Threats & Alerts</a>
            <a href="remote-terminal.php"><i class="fas fa-terminal"></i> Remote Terminal</a>
            <a href="task-manager.php"><i class="fas fa-tasks"></i> Task Manager</a>
            <a href="email-settings.php" class="active"><i class="fas fa-envelope"></i> Email Settings</a>
            <a href="settings.php"><i class="fas fa-cog"></i> Settings</a>
        </div>
        <div class="user-menu">
            <div style="text-align: right; font-size: 13px;">
                <div style="font-weight: 600; color: #333;"><?php echo htmlspecialchars($user['username']); ?></div>
                <div style="color: #999;"><?php echo htmlspecialchars(ucfirst($user['role'])); ?></div>
            </div>
            <a href="?logout=1" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <h1 class="page-title">
            <i class="fas fa-envelope"></i> Email Settings
        </h1>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo $message_type; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <!-- SMTP Configuration -->
        <div class="card">
            <div class="card-title">
                <i class="fas fa-server"></i> SMTP Configuration
            </div>
            
            <form method="POST" action="">
                <input type="hidden" name="action" value="save_settings">
                
                <div class="section">
                    <div class="section-title">SMTP Server Settings</div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="smtp_host">SMTP Host</label>
                            <input type="text" id="smtp_host" name="smtp_host" 
                                   value="<?php echo htmlspecialchars($email_settings['smtp_host']); ?>"
                                   placeholder="e.g., smtp.gmail.com">
                            <div class="hint">SMTP server hostname or IP address</div>
                        </div>
                        
                        <div class="form-group">
                            <label for="smtp_port">SMTP Port</label>
                            <input type="number" id="smtp_port" name="smtp_port" 
                                   value="<?php echo htmlspecialchars($email_settings['smtp_port']); ?>"
                                   placeholder="587">
                            <div class="hint">Usually 587 (TLS) or 465 (SSL)</div>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="smtp_user">SMTP Username</label>
                            <input type="text" id="smtp_user" name="smtp_user" 
                                   value="<?php echo htmlspecialchars($email_settings['smtp_user']); ?>"
                                   placeholder="your-email@gmail.com">
                            <div class="hint">SMTP authentication username</div>
                        </div>
                        
                        <div class="form-group">
                            <label for="smtp_pass">SMTP Password</label>
                            <input type="password" id="smtp_pass" name="smtp_pass" 
                                   value="<?php echo htmlspecialchars($email_settings['smtp_pass']); ?>"
                                   placeholder="••••••••">
                            <div class="hint">SMTP authentication password</div>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">Email Settings</div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="from_email">From Email Address</label>
                            <input type="email" id="from_email" name="from_email" 
                                   value="<?php echo htmlspecialchars($email_settings['from_email']); ?>"
                                   placeholder="siem@company.com">
                            <div class="hint">Email address that alerts will be sent from</div>
                        </div>
                        
                        <div class="form-group">
                            <label for="from_name">From Name</label>
                            <input type="text" id="from_name" name="from_name" 
                                   value="<?php echo htmlspecialchars($email_settings['from_name']); ?>"
                                   placeholder="SIEM Alert System">
                            <div class="hint">Display name for alert emails</div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="use_smtp" name="use_smtp" 
                                   <?php echo $email_settings['use_smtp'] ? 'checked' : ''; ?>>
                            <label for="use_smtp">Use SMTP (check this box if you have SMTP credentials)</label>
                        </div>
                        <div class="hint">If unchecked, will use PHP mail() function</div>
                    </div>
                    
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enable_notifications" name="enable_notifications" 
                                   <?php echo $email_settings['enable_notifications'] ? 'checked' : ''; ?>>
                            <label for="enable_notifications">Enable Email Notifications</label>
                        </div>
                        <div class="hint">Enable automatic email notifications for alerts</div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">Alert Recipients by Severity</div>
                    
                    <div class="form-group">
                        <label for="critical_recipients">Critical Alert Recipients</label>
                        <textarea id="critical_recipients" name="critical_recipients" 
                                  placeholder="soc@company.com&#10;manager@company.com"><?php echo htmlspecialchars($email_settings['critical_recipients']); ?></textarea>
                        <div class="hint">Email addresses (one per line) for critical alerts</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="warning_recipients">Warning Alert Recipients</label>
                        <textarea id="warning_recipients" name="warning_recipients" 
                                  placeholder="soc@company.com"><?php echo htmlspecialchars($email_settings['warning_recipients']); ?></textarea>
                        <div class="hint">Email addresses (one per line) for warning alerts</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="info_recipients">Informational Alert Recipients</label>
                        <textarea id="info_recipients" name="info_recipients" 
                                  placeholder="logs@company.com"><?php echo htmlspecialchars($email_settings['info_recipients']); ?></textarea>
                        <div class="hint">Email addresses (one per line) for informational alerts</div>
                    </div>
                </div>
                
                <div class="button-group">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Settings
                    </button>
                </div>
            </form>
        </div>

        <!-- Testing Section -->
        <div class="card">
            <div class="card-title">
                <i class="fas fa-flask"></i> Test Configuration
            </div>
            
            <form method="POST" action="">
                <div class="section">
                    <div class="section-title">SMTP Connection Test</div>
                    <p style="margin-bottom: 15px; color: #666; font-size: 14px;">
                        Test your SMTP server connection to ensure it's properly configured.
                    </p>
                    
                    <input type="hidden" name="action" value="test_connection">
                    <input type="hidden" name="smtp_host" value="<?php echo htmlspecialchars($email_settings['smtp_host']); ?>">
                    <input type="hidden" name="smtp_port" value="<?php echo htmlspecialchars($email_settings['smtp_port']); ?>">
                    
                    <button type="submit" class="btn btn-secondary">
                        <i class="fas fa-plug"></i> Test SMTP Connection
                    </button>
                </div>
            </form>
            
            <form method="POST" action="">
                <div class="section">
                    <div class="section-title">Send Test Email</div>
                    <p style="margin-bottom: 15px; color: #666; font-size: 14px;">
                        Send a test email to verify your configuration is working correctly.
                    </p>
                    
                    <div class="form-group">
                        <label for="test_email">Test Email Address</label>
                        <input type="email" id="test_email" name="test_email" 
                               placeholder="your-email@company.com" required>
                        <div class="hint">Email address to send test alert to</div>
                    </div>
                    
                    <input type="hidden" name="action" value="send_test_email">
                    
                    <button type="submit" class="btn btn-success">
                        <i class="fas fa-envelope"></i> Send Test Email
                    </button>
                </div>
            </form>
        </div>

        <!-- Information Section -->
        <div class="card">
            <div class="card-title">
                <i class="fas fa-info-circle"></i> Configuration Help
            </div>
            
            <div style="color: #666; font-size: 14px; line-height: 1.8;">
                <h3 style="margin-top: 15px; margin-bottom: 10px; color: #333;">Gmail Configuration</h3>
                <ul style="margin-left: 20px; margin-bottom: 15px;">
                    <li>SMTP Host: <code>smtp.gmail.com</code></li>
                    <li>SMTP Port: <code>587</code></li>
                    <li>Username: Your Gmail address</li>
                    <li>Password: <a href="https://myaccount.google.com/apppasswords" target="_blank">App Password</a> (not your regular password)</li>
                </ul>
                
                <h3 style="margin-top: 15px; margin-bottom: 10px; color: #333;">Office 365 Configuration</h3>
                <ul style="margin-left: 20px; margin-bottom: 15px;">
                    <li>SMTP Host: <code>smtp.office365.com</code></li>
                    <li>SMTP Port: <code>587</code></li>
                    <li>Username: Your Office 365 email</li>
                    <li>Password: Your Office 365 password</li>
                </ul>
                
                <h3 style="margin-top: 15px; margin-bottom: 10px; color: #333;">Custom SMTP Server</h3>
                <ul style="margin-left: 20px;">
                    <li>Contact your email provider for SMTP details</li>
                    <li>Usually port 587 (TLS) or 465 (SSL)</li>
                    <li>Ensure your server allows SMTP connections</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
