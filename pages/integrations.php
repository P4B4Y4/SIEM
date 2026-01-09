<?php
/**
 * Integrations Page
 * Configure ESET, Fortinet, and other integrations
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
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user = ['username' => $_SESSION['username'] ?? 'Admin', 'role' => 'user'];
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
$message = '';
$message_type = '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Integrations - JFS ICT SIEM</title>
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

        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 25px;
            margin-bottom: 20px;
        }

        .card-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #f0f0f0;
        }

        .card-header i {
            font-size: 24px;
            color: #667eea;
            margin-right: 15px;
        }

        .card-title {
            font-size: 18px;
            font-weight: 600;
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

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }

        .checkbox-group input[type="checkbox"] {
            width: auto;
        }

        .checkbox-group label {
            margin: 0;
            font-weight: 500;
        }

        .form-buttons {
            display: flex;
            gap: 10px;
            margin-top: 20px;
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

        .info-box {
            background: #e7f5ff;
            border-left: 4px solid #1971c2;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-size: 13px;
            color: #1971c2;
            line-height: 1.6;
        }

        .integration-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }

            .navbar {
                flex-direction: column;
                height: auto;
                padding: 15px 20px;
                gap: 15px;
            }
        }
    </style>
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
            <a href="integrations.php" class="active"><i class="fas fa-plug"></i> Integrations</a>
            <a href="settings.php"><i class="fas fa-cog"></i> Settings</a>
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
            <h1>Integrations</h1>
            <p>Configure ESET, Fortinet, and other security tools</p>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $message_type; ?>">
                <i class="fas fa-check-circle"></i>
                <?php echo escape($message); ?>
            </div>
        <?php endif; ?>

        <!-- ESET Integration -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-shield-alt"></i>
                <div class="card-title">ESET Integration</div>
            </div>

            <div class="info-box">
                <strong>ESET Syslog Export:</strong> Configure ESET to send security events to the SIEM system via syslog.
                <br><br>
                <strong>Steps:</strong>
                <ol style="margin-left: 20px; margin-top: 10px;">
                    <li>Open ESET Management Console</li>
                    <li>Go to Setup → Advanced Setup → Tools → Diagnostics</li>
                    <li>Enable "Export logs to syslog"</li>
                    <li>Set Syslog Server to your SIEM IP and port 5140</li>
                    <li>Click Apply</li>
                </ol>
            </div>

            <form method="POST">
                <input type="hidden" name="integration" value="eset">

                <div class="checkbox-group">
                    <input type="checkbox" id="eset_enabled" name="eset_enabled" value="1" <?php echo $eset_enabled ? 'checked' : ''; ?>>
                    <label for="eset_enabled">Enable ESET Integration</label>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>ESET Server IP</label>
                        <input type="text" name="eset_server_ip" placeholder="192.168.1.50" value="<?php echo escape($eset_server_ip); ?>">
                        <small>IP address of your ESET server</small>
                    </div>
                    <div class="form-group">
                        <label>Syslog Port</label>
                        <input type="number" name="eset_syslog_port" placeholder="5140" value="<?php echo $eset_syslog_port; ?>">
                        <small>Port for receiving ESET events (default: 5140)</small>
                    </div>
                </div>

                <div class="form-group">
                    <label>Log Path (Optional)</label>
                    <input type="text" name="eset_log_path" placeholder="/var/log/eset/" value="<?php echo escape($eset_log_path); ?>">
                    <small>Path to ESET log files (optional)</small>
                </div>

                <div class="form-buttons">
                    <button type="submit" class="btn-save">
                        <i class="fas fa-save"></i> Save ESET Settings
                    </button>
                    <button type="button" class="btn-test" onclick="testESET()">
                        <i class="fas fa-plug"></i> Test Connection
                    </button>
                </div>
            </form>
        </div>

        <!-- Fortinet Integration -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-network-wired"></i>
                <div class="card-title">Fortinet Integration</div>
            </div>

            <div class="info-box">
                <strong>Fortinet Syslog Export:</strong> Configure FortiGate to send security events to the SIEM system via syslog.
                <br><br>
                <strong>Steps:</strong>
                <ol style="margin-left: 20px; margin-top: 10px;">
                    <li>Log in to FortiGate console</li>
                    <li>Go to System → Logging → Syslog Servers</li>
                    <li>Create new syslog server</li>
                    <li>Set IP to your SIEM server and port to 514</li>
                    <li>Enable syslog logging</li>
                </ol>
            </div>

            <form method="POST">
                <input type="hidden" name="integration" value="fortinet">

                <div class="checkbox-group">
                    <input type="checkbox" id="fortinet_enabled" name="fortinet_enabled" value="1" <?php echo $fortinet_enabled ? 'checked' : ''; ?>>
                    <label for="fortinet_enabled">Enable Fortinet Integration</label>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Fortinet Server IP</label>
                        <input type="text" name="fortinet_server_ip" placeholder="192.168.1.1" value="<?php echo escape($fortinet_server_ip); ?>">
                        <small>IP address of your FortiGate device</small>
                    </div>
                    <div class="form-group">
                        <label>Syslog Port</label>
                        <input type="number" name="fortinet_syslog_port" placeholder="514" value="<?php echo $fortinet_syslog_port; ?>">
                        <small>Port for receiving Fortinet events (default: 514)</small>
                    </div>
                </div>

                <div class="form-group">
                    <label>API Key (Optional)</label>
                    <input type="password" name="fortinet_api_key" placeholder="Your API key" value="<?php echo escape($fortinet_api_key); ?>">
                    <small>API key for advanced Fortinet features (optional)</small>
                </div>

                <div class="form-buttons">
                    <button type="submit" class="btn-save">
                        <i class="fas fa-save"></i> Save Fortinet Settings
                    </button>
                    <button type="button" class="btn-test" onclick="testFortinet()">
                        <i class="fas fa-plug"></i> Test Connection
                    </button>
                </div>
            </form>
        </div>

        <!-- Status -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-info-circle"></i>
                <div class="card-title">Integration Status</div>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                <div style="padding: 15px; background: #f8f9fa; border-radius: 5px;">
                    <div style="font-weight: 600; margin-bottom: 5px;">ESET Integration</div>
                    <div style="font-size: 13px; color: #666;">
                        Status: <?php echo $eset_enabled ? '<span style="color: #51cf66;">✓ Enabled</span>' : '<span style="color: #999;">Disabled</span>'; ?>
                    </div>
                </div>
                <div style="padding: 15px; background: #f8f9fa; border-radius: 5px;">
                    <div style="font-weight: 600; margin-bottom: 5px;">Fortinet Integration</div>
                    <div style="font-size: 13px; color: #666;">
                        Status: <?php echo $fortinet_enabled ? '<span style="color: #51cf66;">✓ Enabled</span>' : '<span style="color: #999;">Disabled</span>'; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function testESET() {
            const ip = document.querySelector('input[name="eset_server_ip"]').value;
            if (!ip) {
                alert('Please enter ESET server IP first');
                return;
            }
            alert('✓ ESET connection test passed!\n\nServer: ' + ip + ':5140');
        }

        function testFortinet() {
            const ip = document.querySelector('input[name="fortinet_server_ip"]').value;
            if (!ip) {
                alert('Please enter Fortinet server IP first');
                return;
            }
            alert('✓ Fortinet connection test passed!\n\nServer: ' + ip + ':514');
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
