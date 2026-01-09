<?php
/**
 * Settings Page
 * Application configuration and settings management
 */

session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/settings.php';

// Ensure logs directory exists
if (function_exists('ensureDirectory') && defined('LOG_DIR')) {
    ensureDirectory(LOG_DIR);
}

// Check authentication
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$user = ['username' => $_SESSION['username'] ?? 'Admin', 'role' => 'user'];
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
$message = '';
$message_type = '';

// Load SMTP + email notification settings from config/settings.json (authoritative)
$smtp_settings = (array)getSetting('smtp', []);
$email_notifications_settings = (array)getSetting('email_notifications', []);

// Load email settings from file
$email_settings_file = '../config/email_settings.json';
$email_settings = [];
if (file_exists($email_settings_file)) {
    $email_settings = json_decode(file_get_contents($email_settings_file), true);
}

// Defaults
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
], is_array($email_settings) ? $email_settings : []);

// Overlay defaults from settings.json so the UI reflects what the system actually uses
$email_settings['smtp_host'] = (string)($smtp_settings['host'] ?? $email_settings['smtp_host']);
$email_settings['smtp_port'] = (int)($smtp_settings['port'] ?? $email_settings['smtp_port']);
$email_settings['smtp_user'] = (string)($smtp_settings['username'] ?? $email_settings['smtp_user']);
$email_settings['smtp_pass'] = (string)($smtp_settings['password'] ?? $email_settings['smtp_pass']);
$email_settings['from_email'] = (string)($smtp_settings['from_email'] ?? $email_settings['from_email']);
$email_settings['from_name'] = (string)($smtp_settings['from_name'] ?? $email_settings['from_name']);
$email_settings['use_smtp'] = (bool)($smtp_settings['enabled'] ?? $email_settings['use_smtp']);
$email_settings['enable_notifications'] = (bool)($email_notifications_settings['enabled'] ?? $email_settings['enable_notifications']);

// If no severity-based recipients are configured in email_settings.json, fall back to email_notifications.default_recipients
if (
    trim((string)$email_settings['critical_recipients']) === '' &&
    trim((string)$email_settings['warning_recipients']) === '' &&
    trim((string)$email_settings['info_recipients']) === ''
) {
    $fallbackRecipients = (string)($email_notifications_settings['default_recipients'] ?? '');
    if ($fallbackRecipients !== '') {
        $email_settings['critical_recipients'] = $fallbackRecipients;
        $email_settings['warning_recipients'] = $fallbackRecipients;
        $email_settings['info_recipients'] = $fallbackRecipients;
    }
}

// Handle settings forms
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['category'])) {
    $category = $_POST['category'];

    if ($category === 'email') {
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

        // Persist to legacy email_settings.json (UI-specific recipients)
        $okLegacy = file_put_contents($email_settings_file, json_encode($email_settings, JSON_PRETTY_PRINT)) !== false;

        // Persist authoritative SMTP + email notification settings to config/settings.json
        $okSettings = true;
        $okSettings = $okSettings && setSetting('smtp.host', (string)$email_settings['smtp_host']);
        $okSettings = $okSettings && setSetting('smtp.port', (int)$email_settings['smtp_port']);
        $okSettings = $okSettings && setSetting('smtp.username', (string)$email_settings['smtp_user']);
        $okSettings = $okSettings && setSetting('smtp.password', (string)$email_settings['smtp_pass']);
        $okSettings = $okSettings && setSetting('smtp.from_email', (string)$email_settings['from_email']);
        $okSettings = $okSettings && setSetting('smtp.from_name', (string)$email_settings['from_name']);
        $okSettings = $okSettings && setSetting('smtp.enabled', (bool)$email_settings['use_smtp']);
        $okSettings = $okSettings && setSetting('email_notifications.enabled', (bool)$email_settings['enable_notifications']);

        // Default recipients: prefer critical list, else warning, else info
        $defaultRecipients = trim((string)$email_settings['critical_recipients']);
        if ($defaultRecipients === '') {
            $defaultRecipients = trim((string)$email_settings['warning_recipients']);
        }
        if ($defaultRecipients === '') {
            $defaultRecipients = trim((string)$email_settings['info_recipients']);
        }
        $okSettings = $okSettings && setSetting('email_notifications.default_recipients', $defaultRecipients);

        if ($okLegacy && $okSettings) {
            $message = 'Email settings saved successfully!';
            $message_type = 'success';
        } else {
            $message = 'Failed to save email settings';
            $message_type = 'error';
        }
    }
}

$ai_enabled = (bool)getSetting('ai.enabled', false);
$ai_provider = (string)getSetting('ai.provider', 'groq');
$ai_model = (string)getSetting('ai.model', 'openai/gpt-oss-20b');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - JFS ICT SIEM</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #333;
        }

        .navbar {
            background: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 0 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 70px;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .navbar-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 20px;
            font-weight: 600;
            color: #667eea;
        }

        .navbar-menu {
            display: flex;
            gap: 30px;
            align-items: center;
        }

        .navbar-menu a {
            color: #666;
            text-decoration: none;
            font-size: 14px;
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
            padding: 8px 16px;
            background: #ff6b6b;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px;
        }

        .page-header {
            margin-bottom: 30px;
        }

        .page-header h1 {
            font-size: 32px;
            margin-bottom: 5px;
        }

        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-success {
            background: #e6ffed;
            color: #2d6a4f;
            border: 1px solid #52b788;
        }

        .alert-error {
            background: #ffe6e6;
            color: #6a2d2d;
            border: 1px solid #b85252;
        }

        .settings-container {
            display: grid;
            grid-template-columns: 250px 1fr;
            gap: 30px;
        }

        .settings-menu {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0;
            height: fit-content;
            position: sticky;
            top: 100px;
        }

        .settings-menu a {
            display: block;
            padding: 15px 20px;
            color: #666;
            text-decoration: none;
            border-left: 3px solid transparent;
            transition: all 0.3s;
            font-size: 14px;
        }

        .settings-menu a:hover {
            background: #f8f9fa;
            color: #667eea;
        }

        .settings-menu a.active {
            background: #f0f4ff;
            color: #667eea;
            border-left-color: #667eea;
        }

        .settings-content {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 30px;
        }

        .settings-section {
            display: none;
        }

        .settings-section.active {
            display: block;
        }

        .settings-section h2 {
            font-size: 20px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #f0f0f0;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            font-size: 13px;
            color: #666;
        }

        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 13px;
            font-family: inherit;
        }

        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .form-group textarea {
            resize: vertical;
            min-height: 100px;
        }

        .form-group small {
            display: block;
            margin-top: 5px;
            color: #999;
            font-size: 12px;
        }

        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }

        .form-buttons {
            display: flex;
            gap: 10px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #f0f0f0;
        }

        .btn-save {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }

        .btn-save:hover {
            background: #5568d3;
        }

        .btn-test {
            padding: 10px 20px;
            background: #51cf66;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }

        .btn-test:hover {
            background: #40c057;
        }

        @media (max-width: 768px) {
            .settings-container {
                grid-template-columns: 1fr;
            }

            .settings-menu {
                display: flex;
                overflow-x: auto;
                position: static;
            }

            .settings-menu a {
                flex-shrink: 0;
                border-left: none;
                border-bottom: 3px solid transparent;
            }

            .settings-menu a.active {
                border-left: none;
                border-bottom-color: #667eea;
            }

            .form-row {
                grid-template-columns: 1fr;
            }
        }

    </style>

    <script>
        function saveAISettings() {
            const enabled = document.getElementById('ai_enabled').checked;
            const provider = document.getElementById('ai_provider').value || 'groq';
            const model = document.getElementById('ai_model').value || 'openai/gpt-oss-20b';
            const apiKey = document.getElementById('ai_api_key').value || '';

            fetch('../api/settings.php?action=save_ai', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    enabled: enabled,
                    provider: provider,
                    model: model,
                    api_key: apiKey
                })
            })
            .then(async (response) => {
                const text = await response.text();
                let data = null;
                try {
                    data = JSON.parse(text);
                } catch (e) {
                    throw new Error('Server returned invalid JSON (HTTP ' + response.status + '): ' + (text || '[empty response]'));
                }
                return data;
            })
            .then(data => {
                if (data.success) {
                    alert('✓ AI settings saved');
                    document.getElementById('ai_api_key').value = '';
                } else {
                    alert('✗ Failed to save AI settings: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                alert('✗ Error saving AI settings: ' + error.message);
            });
        }

    </script>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar">
        <div class="navbar-brand">
            <i class="fas fa-shield-alt"></i>
            <span>JFS ICT SIEM</span>
        </div>
        <div class="navbar-menu">
            <a href="dashboard.php"><i class="fas fa-home"></i> Dashboard</a>
            <a href="events.php"><i class="fas fa-list"></i> Events</a>
            <a href="threats.php"><i class="fas fa-exclamation-triangle"></i> Threats & Alerts</a>
            <a href="remote-terminal.php"><i class="fas fa-terminal"></i> Remote Terminal</a>
            <a href="task-manager.php"><i class="fas fa-tasks"></i> Task Manager</a>
            <a href="settings.php" class="active"><i class="fas fa-cog"></i> Settings</a>
        </div>
        <div class="user-menu">
            <div style="text-align: right; font-size: 13px;">
                <div style="font-weight: 600; color: #333;"><?php echo htmlspecialchars($user['username']); ?></div>
                <div style="color: #999;">Administrator</div>
            </div>
            <a href="?logout=1" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <div class="page-header">
            <h1>Settings</h1>
            <p>Manage application configuration and preferences</p>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $message_type; ?>">
                <i class="fas fa-<?php echo $message_type === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                <?php echo escape($message); ?>
            </div>
        <?php endif; ?>

        <div class="settings-container">
            <!-- Settings Menu -->
            <div class="settings-menu">
                <a href="#" class="menu-item active" data-section="general">
                    <i class="fas fa-cog"></i> General
                </a>
                <a href="#" class="menu-item" data-section="database">
                    <i class="fas fa-database"></i> Database
                </a>
                <a href="#" class="menu-item" data-section="security">
                    <i class="fas fa-lock"></i> Security
                </a>
                <a href="#" class="menu-item" data-section="email">
                    <i class="fas fa-envelope"></i> Email
                </a>
                <a href="#" class="menu-item" data-section="ai">
                    <i class="fas fa-robot"></i> AI
                </a>
                <a href="#" class="menu-item" data-section="backup">
                    <i class="fas fa-hdd"></i> Backup
                </a>
            </div>

            <!-- Settings Content -->
            <div class="settings-content">
                <!-- General Settings -->
                <div class="settings-section active" id="general">
                    <h2>General Settings</h2>
                    <form method="POST">
                        <input type="hidden" name="category" value="general">
                        
                        <div class="form-group">
                            <label>Application Name</label>
                            <input type="text" name="app_name" value="<?php echo escape(APP_NAME); ?>" readonly>
                            <small>The name of your SIEM application</small>
                        </div>

                        <div class="form-group">
                            <label>Application Version</label>
                            <input type="text" name="app_version" value="<?php echo escape(APP_VERSION); ?>" readonly>
                            <small>Current application version</small>
                        </div>

                        <div class="form-group">
                            <label>Environment</label>
                            <input type="text" name="environment" value="<?php echo escape(APP_ENVIRONMENT); ?>" readonly>
                            <small>Current environment (production/development)</small>
                        </div>

                        <div class="form-buttons">
                            <button type="submit" class="btn-save">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                        </div>
                    </form>
                </div>

                <!-- AI Settings -->
                <div class="settings-section" id="ai">
                    <h2>AI Configuration</h2>
                    <form onsubmit="event.preventDefault(); saveAISettings();">
                        <div class="form-group">
                            <label>
                                <input type="checkbox" id="ai_enabled" value="1" <?php echo $ai_enabled ? 'checked' : ''; ?>>
                                Enable AI Analysis (Groq)
                            </label>
                            <small>When enabled, Threats page can generate AI summaries and recommendations for alerts</small>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Provider</label>
                                <input type="text" id="ai_provider" value="<?php echo htmlspecialchars($ai_provider); ?>" readonly>
                                <small>Current provider</small>
                            </div>
                            <div class="form-group">
                                <label>Model</label>
                                <input type="text" id="ai_model" value="<?php echo htmlspecialchars($ai_model); ?>">
                                <small>Example: openai/gpt-oss-20b</small>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>Groq API Key</label>
                            <input type="password" id="ai_api_key" placeholder="Enter new Groq API key (leave blank to keep current)">
                            <small>Do not share this key. Leave blank to keep current key.</small>
                        </div>

                        <div class="form-buttons">
                            <button type="submit" class="btn-save">
                                <i class="fas fa-save"></i> Save AI Settings
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Database Settings -->
                <div class="settings-section" id="database">
                    <h2>Database Configuration</h2>
                    <form method="POST">
                        <input type="hidden" name="category" value="database">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label>Database Host</label>
                                <input type="text" name="db_host" value="<?php echo escape(DB_HOST); ?>" readonly>
                            </div>
                            <div class="form-group">
                                <label>Database Name</label>
                                <input type="text" name="db_name" value="<?php echo escape(DB_NAME); ?>" readonly>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Database User</label>
                                <input type="text" name="db_user" value="<?php echo escape(DB_USER); ?>" readonly>
                            </div>
                            <div class="form-group">
                                <label>Database Port</label>
                                <input type="text" name="db_port" value="<?php echo escape(DB_PORT); ?>" readonly>
                            </div>
                        </div>

                        <div class="form-buttons">
                            <button type="button" class="btn-test" onclick="testDatabaseConnection()">
                                <i class="fas fa-plug"></i> Test Connection
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Security Settings -->
                <div class="settings-section" id="security">
                    <h2>Security Configuration</h2>
                    <form method="POST">
                        <input type="hidden" name="category" value="security">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label>Session Timeout (seconds)</label>
                                <input type="number" name="session_timeout" value="<?php echo escape(SESSION_TIMEOUT); ?>" readonly>
                                <small>How long before a session expires</small>
                            </div>
                            <div class="form-group">
                                <label>Password Minimum Length</label>
                                <input type="number" name="password_min_length" value="<?php echo escape(PASSWORD_MIN_LENGTH); ?>" readonly>
                                <small>Minimum password length requirement</small>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Max Login Attempts</label>
                                <input type="number" name="max_login_attempts" value="<?php echo escape(MAX_LOGIN_ATTEMPTS); ?>" readonly>
                                <small>Failed attempts before account lockout</small>
                            </div>
                            <div class="form-group">
                                <label>Lockout Duration (seconds)</label>
                                <input type="number" name="lockout_duration" value="<?php echo escape(LOCKOUT_DURATION); ?>" readonly>
                                <small>How long to lock account after failed attempts</small>
                            </div>
                        </div>

                        <div class="form-buttons">
                            <button type="submit" class="btn-save">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Email Settings -->
                <div class="settings-section" id="email">
                    <h2>Email Configuration</h2>
                    <form method="POST">
                        <input type="hidden" name="category" value="email">
                        
                        <div class="form-group">
                            <label>SMTP Host</label>
                            <input type="text" name="smtp_host" placeholder="smtp.gmail.com" value="<?php echo htmlspecialchars($email_settings['smtp_host']); ?>">
                            <small>Email server hostname (e.g., smtp.gmail.com, smtp.office365.com)</small>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>SMTP Port</label>
                                <input type="number" name="smtp_port" placeholder="587" value="<?php echo (int)$email_settings['smtp_port']; ?>">
                                <small>Usually 587 (TLS) or 465 (SSL)</small>
                            </div>
                            <div class="form-group">
                                <label>SMTP Username</label>
                                <input type="text" name="smtp_user" placeholder="your-email@gmail.com" value="<?php echo htmlspecialchars($email_settings['smtp_user']); ?>">
                                <small>SMTP authentication username</small>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>SMTP Password</label>
                            <input type="password" name="smtp_pass" placeholder="••••••••" value="<?php echo htmlspecialchars($email_settings['smtp_pass']); ?>">
                            <small>SMTP authentication password (for Gmail use App Password)</small>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>From Email Address</label>
                                <input type="email" name="from_email" placeholder="siem@company.com" value="<?php echo htmlspecialchars($email_settings['from_email']); ?>">
                                <small>Email address alerts will be sent from</small>
                            </div>
                            <div class="form-group">
                                <label>From Name</label>
                                <input type="text" name="from_name" placeholder="SIEM Alert System" value="<?php echo htmlspecialchars($email_settings['from_name']); ?>">
                                <small>Display name for alert emails</small>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>
                                <input type="checkbox" name="use_smtp" value="1" <?php echo $email_settings['use_smtp'] ? 'checked' : ''; ?>>
                                Use SMTP (check if you have SMTP credentials)
                            </label>
                            <small>If unchecked, will use PHP mail() function</small>
                        </div>

                        <div class="form-group">
                            <label>
                                <input type="checkbox" name="enable_notifications" value="1" <?php echo $email_settings['enable_notifications'] ? 'checked' : ''; ?>>
                                Enable Email Notifications
                            </label>
                            <small>Automatically send email notifications for alerts</small>
                        </div>

                        <div class="form-group">
                            <label>Critical Alert Recipients</label>
                            <textarea name="critical_recipients" placeholder="soc@company.com&#10;manager@company.com"><?php echo htmlspecialchars($email_settings['critical_recipients']); ?></textarea>
                            <small>Email addresses for critical alerts (one per line)</small>
                        </div>

                        <div class="form-group">
                            <label>Warning Alert Recipients</label>
                            <textarea name="warning_recipients" placeholder="soc@company.com"><?php echo htmlspecialchars($email_settings['warning_recipients']); ?></textarea>
                            <small>Email addresses for warning alerts (one per line)</small>
                        </div>

                        <div class="form-group">
                            <label>Informational Alert Recipients</label>
                            <textarea name="info_recipients" placeholder="logs@company.com"><?php echo htmlspecialchars($email_settings['info_recipients']); ?></textarea>
                            <small>Email addresses for informational alerts (one per line)</small>
                        </div>

                        <div class="form-buttons">
                            <button type="button" class="btn-test" onclick="testEmailConnection()">
                                <i class="fas fa-plug"></i> Test SMTP Connection
                            </button>
                            <button type="button" class="btn-test" onclick="sendTestEmail()">
                                <i class="fas fa-envelope"></i> Send Test Email
                            </button>
                            <button type="submit" class="btn-save">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Backup Settings -->
                <div class="settings-section" id="backup">
                    <h2>Backup Configuration</h2>
                    <form method="POST">
                        <input type="hidden" name="category" value="backup">
                        
                        <div class="form-group">
                            <label>Backup Path</label>
                            <input type="text" name="backup_path" placeholder="/backups/siem/" readonly>
                            <small>Location where backups are stored</small>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Backup Frequency</label>
                                <select name="backup_frequency">
                                    <option>Daily</option>
                                    <option>Weekly</option>
                                    <option>Monthly</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Retention Days</label>
                                <input type="number" name="retention_days" placeholder="30" value="30">
                                <small>How long to keep backups</small>
                            </div>
                        </div>

                        <div class="form-buttons">
                            <button type="button" class="btn-test" onclick="runBackup()">
                                <i class="fas fa-download"></i> Run Backup Now
                            </button>
                            <button type="submit" class="btn-save">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Menu item click handler
        document.querySelectorAll('.menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.getAttribute('data-section');
                
                // Hide all sections
                document.querySelectorAll('.settings-section').forEach(s => {
                    s.classList.remove('active');
                });
                
                // Remove active class from all menu items
                document.querySelectorAll('.menu-item').forEach(m => {
                    m.classList.remove('active');
                });
                
                // Show selected section
                document.getElementById(section).classList.add('active');
                item.classList.add('active');
            });
        });

        function testDatabaseConnection() {
            const host = document.querySelector('input[name="db_host"]').value || '<?php echo DB_HOST; ?>';
            const name = document.querySelector('input[name="db_name"]').value || '<?php echo DB_NAME; ?>';
            const user = document.querySelector('input[name="db_user"]').value || '<?php echo DB_USER; ?>';
            
            fetch('../api/settings.php?action=test_database', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    host: host,
                    user: user,
                    name: name
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('✓ Database connection successful!');
                } else {
                    alert('✗ Database connection failed: ' + data.message);
                }
            })
            .catch(error => {
                alert('✗ Error testing connection: ' + error.message);
            });
        }

        function testEmailConnection() {
            const host = document.querySelector('input[name="smtp_host"]').value;
            const port = document.querySelector('input[name="smtp_port"]').value || 587;
            
            if (!host) {
                alert('Please enter SMTP host first');
                return;
            }
            
            fetch('../api/send-alert-email.php?action=test_smtp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    host: host,
                    port: port
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('✓ SMTP connection successful!');
                } else {
                    alert('✗ SMTP connection failed: ' + data.error);
                }
            })
            .catch(error => {
                alert('✗ Error testing connection: ' + error.message);
            });
        }

        function sendTestEmail() {
            const email = prompt('Enter your email address to receive test alert:');
            
            if (!email) {
                return;
            }
            
            const testAlert = {
                alert_id: 'TEST_ALERT_001',
                title: 'Test Alert - Email Configuration Verification',
                alert_level: 'Informational',
                timestamp: new Date().toLocaleString(),
                computer: 'TEST-SYSTEM',
                source: 'Email Settings',
                category: 'System',
                severity: 'low',
                anomaly: 'No',
                reason: 'This is a test email to verify SMTP configuration',
                recommendation: 'If you received this email, your SMTP settings are configured correctly.',
                escalation: 'Review in normal shift'
            };
            
            fetch('../api/send-alert-email.php?action=send_alert', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    alert: testAlert,
                    recipient: email
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('✓ Test email sent successfully to ' + email + '!\n\nCheck your inbox (and spam folder) for the test alert.');
                } else {
                    const err = data.error ? ('\n\nError: ' + data.error) : '';
                    alert('✗ Failed to send test email: ' + data.message + err);
                }
            })
            .catch(error => {
                alert('✗ Error sending test email: ' + error.message);
            });
        }

        function runBackup() {
            if (confirm('Are you sure you want to run a backup now? This may take a few minutes...')) {
                fetch('../api/settings.php?action=backup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('✓ Backup completed successfully!\n\nFile: ' + data.file + '\nSize: ' + data.size);
                    } else {
                        alert('✗ Backup failed: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('✗ Error running backup: ' + error.message);
                });
            }
        }
    </script>
    
    <?php
    // Handle logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit;
    }
    
    $db->close();
    ?>
</body>
</html>
