<?php
/**
 * Agent Deployment Page
 * Instructions and downloads for deploying SIEM agents
 */

session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

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

// Get agent count
$result = $db->query("SELECT COUNT(*) as count FROM agents WHERE status = 'active'");
$agent_count = $result ? $result->fetch_assoc()['count'] : 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Deployment - JFS ICT SIEM</title>
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

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            text-align: center;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 13px;
            color: #999;
            text-transform: uppercase;
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

        .steps {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .step {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }

        .step-number {
            display: inline-block;
            width: 30px;
            height: 30px;
            background: #667eea;
            color: white;
            border-radius: 50%;
            text-align: center;
            line-height: 30px;
            font-weight: 600;
            margin-bottom: 10px;
        }

        .step-title {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #333;
        }

        .step-description {
            font-size: 13px;
            color: #666;
            line-height: 1.6;
        }

        .code-block {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            overflow-x: auto;
            margin: 10px 0;
        }

        .btn-primary {
            display: inline-block;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
            margin-top: 10px;
        }

        .btn-primary:hover {
            background: #5568d3;
        }

        .info-box {
            background: #e7f5ff;
            border-left: 4px solid #1971c2;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-size: 13px;
            color: #1971c2;
        }

        .success-box {
            background: #e6ffed;
            border-left: 4px solid #2f9e44;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-size: 13px;
            color: #2f9e44;
        }

        @media (max-width: 768px) {
            .steps {
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
            <a href="agent-deployment.php" class="active"><i class="fas fa-server"></i> Agents</a>
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
            <h1>Agent Deployment</h1>
            <p>Deploy SIEM agents to remote PCs to start collecting security events</p>
        </div>

        <!-- Stats -->
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value"><?php echo $agent_count; ?></div>
                <div class="stat-label">Active Agents</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">9999</div>
                <div class="stat-label">Collector Port</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">TCP</div>
                <div class="stat-label">Connection Type</div>
            </div>
        </div>

        <!-- Download Section -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-download"></i>
                <div class="card-title">Download Agent</div>
            </div>
            <p>The JFS SIEM Agent is a professional Windows application with a modern GUI for easy configuration and deployment.</p>
            
            <div class="success-box">
                <i class="fas fa-check-circle"></i>
                <strong>Professional EXE Agent Available!</strong>
                <br><br>
                Modern Windows GUI - No command line needed!
                <br><br>
                <strong>File:</strong> JFS_SIEM_Agent.exe (10.8 MB)
                <br><strong>Location:</strong> <code>agents/JFS_SIEM_Agent.exe</code>
                <br><strong>Requirements:</strong> Windows 7+
            </div>

            <h3 style="margin-top: 20px; margin-bottom: 10px;">Agent Features</h3>
            <ul style="margin-left: 20px; line-height: 1.8;">
                <li>✓ Modern Windows GUI interface</li>
                <li>✓ Collects Windows Event Logs automatically</li>
                <li>✓ Sends events to SIEM collector (port 9999)</li>
                <li>✓ Easy configuration (just enter IP)</li>
                <li>✓ Connection testing built-in</li>
                <li>✓ Runs as Windows Service</li>
                <li>✓ Auto-starts on system boot</li>
                <li>✓ Auto-restarts on crash</li>
                <li>✓ Real-time status display</li>
                <li>✓ Event counter</li>
            </ul>

            <h3 style="margin-top: 20px; margin-bottom: 10px;">Quick Start (3 Steps)</h3>
            <ol style="margin-left: 20px; line-height: 1.8;">
                <li>Copy <code>JFS_SIEM_Agent.exe</code> to remote PC</li>
                <li>Double-click to run the EXE</li>
                <li>Enter your SIEM server IP and click "Install Service"</li>
            </ol>
        </div>

        <!-- Deployment Steps -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-tasks"></i>
                <div class="card-title">Deployment Steps</div>
            </div>

            <div class="steps">
                <div class="step">
                    <div class="step-number">1</div>
                    <div class="step-title">Copy EXE to SIEM Folder</div>
                    <div class="step-description">
                        Copy <code>JFS_SIEM_Agent.exe</code> from original location to <code>agents/</code> folder
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">2</div>
                    <div class="step-title">Copy to Remote PC</div>
                    <div class="step-description">
                        Copy <code>JFS_SIEM_Agent.exe</code> to any folder on the remote PC
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">3</div>
                    <div class="step-title">Run the EXE</div>
                    <div class="step-description">
                        Double-click <code>JFS_SIEM_Agent.exe</code> to open the GUI
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">4</div>
                    <div class="step-title">Enter SIEM Server IP</div>
                    <div class="step-description">
                        In the GUI, enter your SIEM server IP address (e.g., 192.168.1.100)
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">5</div>
                    <div class="step-title">Test Connection</div>
                    <div class="step-description">
                        Click "Test Connection" button to verify the agent can reach your SIEM server
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">6</div>
                    <div class="step-title">Install Service</div>
                    <div class="step-description">
                        Click "Install Service" button to install the agent as a Windows Service
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">7</div>
                    <div class="step-title">Verify Running</div>
                    <div class="step-description">
                        Open Windows Services (services.msc) and verify "JFSSIEMAgent" is running
                    </div>
                </div>

                <div class="step">
                    <div class="step-number">8</div>
                    <div class="step-title">Monitor Events</div>
                    <div class="step-description">
                        Go to SIEM Dashboard to see events from the remote PC
                    </div>
                </div>
            </div>
        </div>

        <!-- Configuration -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-cog"></i>
                <div class="card-title">Agent Configuration</div>
            </div>

            <h3 style="margin-bottom: 10px;">Configuration Variables</h3>
            <div class="code-block">
// Edit these in simple-agent.php:

$SIEM_SERVER = '192.168.1.100';    // Your SIEM server IP
$SIEM_PORT = 9999;                 // Collector port
$AGENT_NAME = 'PC-001';            // Your PC name
$COLLECTION_INTERVAL = 10;         // Seconds between collections
            </div>

            <h3 style="margin-top: 20px; margin-bottom: 10px;">How to Configure</h3>
            <ol style="margin-left: 20px; line-height: 1.8;">
                <li>Open <code>simple-agent.php</code> in a text editor</li>
                <li>Find line: <code>$SIEM_SERVER = '192.168.1.100';</code></li>
                <li>Replace with your SIEM server IP (e.g., '192.168.1.50')</li>
                <li>Find line: <code>$AGENT_NAME = 'PC-001';</code></li>
                <li>Replace with your PC name (e.g., 'PC-OFFICE-01')</li>
                <li>Save the file</li>
                <li>Run: <code>php simple-agent.php</code></li>
            </ol>

            <h3 style="margin-top: 20px; margin-bottom: 10px;">Example Configuration</h3>
            <div class="code-block">
$SIEM_SERVER = '192.168.1.50';     // Change to your SIEM IP
$SIEM_PORT = 9999;                 // Keep as 9999
$AGENT_NAME = 'PC-OFFICE-01';      // Your PC name
$COLLECTION_INTERVAL = 10;         // Collect every 10 seconds
            </div>
        </div>

        <!-- Troubleshooting -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-wrench"></i>
                <div class="card-title">Troubleshooting</div>
            </div>

            <h3 style="margin-bottom: 10px;">Connection Failed</h3>
            <ul style="margin-left: 20px; line-height: 1.8;">
                <li>Verify SIEM server IP is correct</li>
                <li>Verify port 9999 is open in firewall</li>
                <li>Verify collector is running: <code>netstat -ano | findstr :9999</code></li>
                <li>Check network connectivity: <code>ping &lt;SIEM-IP&gt;</code></li>
            </ul>

            <h3 style="margin-top: 20px; margin-bottom: 10px;">Service Won't Start</h3>
            <ul style="margin-left: 20px; line-height: 1.8;">
                <li>Check Windows Services: <code>services.msc</code></li>
                <li>Verify service is set to "Automatic" startup</li>
                <li>Check event logs for errors</li>
                <li>Reinstall the service</li>
            </ul>

            <h3 style="margin-top: 20px; margin-bottom: 10px;">Events Not Arriving</h3>
            <ul style="margin-left: 20px; line-height: 1.8;">
                <li>Verify agent service is running</li>
                <li>Check agent logs for errors</li>
                <li>Verify database connection on SIEM server</li>
                <li>Check SIEM dashboard for new events</li>
            </ul>
        </div>

        <!-- Quick Links -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-link"></i>
                <div class="card-title">Quick Links</div>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <a href="dashboard.php" class="btn-primary" style="text-align: center;">
                    <i class="fas fa-chart-line"></i> View Dashboard
                </a>
                <a href="events.php" class="btn-primary" style="text-align: center;">
                    <i class="fas fa-list"></i> View Events
                </a>
                <a href="integrations.php" class="btn-primary" style="text-align: center;">
                    <i class="fas fa-plug"></i> Configure Integrations
                </a>
                <a href="settings.php" class="btn-primary" style="text-align: center;">
                    <i class="fas fa-cog"></i> Settings
                </a>
            </div>
        </div>
    </div>
    
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
