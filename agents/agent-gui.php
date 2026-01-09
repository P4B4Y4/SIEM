<?php
/**
 * SIEM Agent GUI
 * Web-based interface for agent configuration and control
 * Access: http://localhost/SIEM/agents/agent-gui.php
 */

session_start();

// Configuration file
$config_file = __DIR__ . '/agent-config.json';

// Default configuration
$default_config = [
    'siem_server' => '192.168.1.100',
    'siem_port' => 9999,
    'agent_name' => 'PC-001',
    'collection_interval' => 10,
    'enabled' => false,
    'status' => 'stopped'
];

// Load or create configuration
if (file_exists($config_file)) {
    $config = json_decode(file_get_contents($config_file), true);
} else {
    $config = $default_config;
    file_put_contents($config_file, json_encode($config, JSON_PRETTY_PRINT));
}

// Handle form submission
$message = '';
$message_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'save_config') {
        $config['siem_server'] = $_POST['siem_server'] ?? $config['siem_server'];
        $config['siem_port'] = (int)($_POST['siem_port'] ?? $config['siem_port']);
        $config['agent_name'] = $_POST['agent_name'] ?? $config['agent_name'];
        $config['collection_interval'] = (int)($_POST['collection_interval'] ?? $config['collection_interval']);
        
        file_put_contents($config_file, json_encode($config, JSON_PRETTY_PRINT));
        $message = 'Configuration saved successfully!';
        $message_type = 'success';
    } elseif ($action === 'test_connection') {
        $server = $_POST['siem_server'] ?? $config['siem_server'];
        $port = (int)($_POST['siem_port'] ?? $config['siem_port']);
        
        $socket = @fsockopen($server, $port, $errno, $errstr, 3);
        if ($socket) {
            fclose($socket);
            $message = "✓ Connection successful! SIEM server is reachable at $server:$port";
            $message_type = 'success';
        } else {
            $message = "✗ Connection failed! Cannot reach $server:$port - $errstr";
            $message_type = 'error';
        }
    } elseif ($action === 'start_agent') {
        $config['enabled'] = true;
        $config['status'] = 'running';
        file_put_contents($config_file, json_encode($config, JSON_PRETTY_PRINT));
        $message = 'Agent started! It will now collect Windows Event Logs.';
        $message_type = 'success';
    } elseif ($action === 'stop_agent') {
        $config['enabled'] = false;
        $config['status'] = 'stopped';
        file_put_contents($config_file, json_encode($config, JSON_PRETTY_PRINT));
        $message = 'Agent stopped.';
        $message_type = 'success';
    }
}

// Get event count (if collector is running)
$event_count = 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIEM Agent GUI</title>
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
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 600px;
            width: 100%;
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 28px;
            margin-bottom: 5px;
        }

        .header p {
            font-size: 14px;
            opacity: 0.9;
        }

        .content {
            padding: 30px;
        }

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 14px;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .status-box {
            background: #f8f9fa;
            border: 2px solid #dee2e6;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
            text-align: center;
        }

        .status-indicator {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
            animation: pulse 2s infinite;
        }

        .status-indicator.running {
            background: #51cf66;
        }

        .status-indicator.stopped {
            background: #ff6b6b;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .status-text {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .status-details {
            font-size: 13px;
            color: #666;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            font-size: 13px;
            color: #333;
        }

        .form-group input,
        .form-group select {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 13px;
            font-family: inherit;
            transition: border-color 0.3s;
        }

        .form-group input:focus,
        .form-group select:focus {
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

        .button-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 25px;
        }

        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn-primary {
            background: #667eea;
            color: white;
            grid-column: 1 / -1;
        }

        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }

        .btn-success {
            background: #51cf66;
            color: white;
        }

        .btn-success:hover {
            background: #40c057;
        }

        .btn-danger {
            background: #ff6b6b;
            color: white;
        }

        .btn-danger:hover {
            background: #ff5252;
        }

        .btn-secondary {
            background: #868e96;
            color: white;
        }

        .btn-secondary:hover {
            background: #748087;
        }

        .info-box {
            background: #e7f5ff;
            border-left: 4px solid #1971c2;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 13px;
            color: #1971c2;
            line-height: 1.6;
        }

        .divider {
            height: 1px;
            background: #eee;
            margin: 25px 0;
        }

        @media (max-width: 600px) {
            .header {
                padding: 20px;
            }

            .header h1 {
                font-size: 24px;
            }

            .content {
                padding: 20px;
            }

            .button-group {
                grid-template-columns: 1fr;
            }

            .btn-primary {
                grid-column: 1;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1><i class="fas fa-robot"></i> SIEM Agent</h1>
            <p>Simple GUI-based agent configuration</p>
        </div>

        <!-- Content -->
        <div class="content">
            <!-- Alert Messages -->
            <?php if ($message): ?>
                <div class="alert alert-<?php echo $message_type; ?>">
                    <i class="fas fa-<?php echo $message_type === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>

            <!-- Status Box -->
            <div class="status-box">
                <div class="status-indicator <?php echo $config['enabled'] ? 'running' : 'stopped'; ?>"></div>
                <div class="status-text">
                    <?php echo $config['enabled'] ? '✓ Agent Running' : '✗ Agent Stopped'; ?>
                </div>
                <div class="status-details">
                    <?php echo $config['agent_name']; ?> → <?php echo $config['siem_server']; ?>:<?php echo $config['siem_port']; ?>
                </div>
            </div>

            <!-- Info Box -->
            <div class="info-box">
                <i class="fas fa-info-circle"></i>
                <strong>How it works:</strong> Configure your SIEM server details, test the connection, then start the agent. It will automatically collect Windows Event Logs and send them to your SIEM server.
            </div>

            <!-- Configuration Form -->
            <form method="POST">
                <h3 style="margin-bottom: 15px; font-size: 16px;">Configuration</h3>

                <div class="form-group">
                    <label for="siem_server">SIEM Server IP Address</label>
                    <input type="text" id="siem_server" name="siem_server" value="<?php echo htmlspecialchars($config['siem_server']); ?>" placeholder="192.168.1.100">
                    <small>IP address of your SIEM server</small>
                </div>

                <div class="form-group">
                    <label for="siem_port">SIEM Server Port</label>
                    <input type="number" id="siem_port" name="siem_port" value="<?php echo $config['siem_port']; ?>" min="1" max="65535">
                    <small>Port number (default: 9999)</small>
                </div>

                <div class="form-group">
                    <label for="agent_name">Agent Name</label>
                    <input type="text" id="agent_name" name="agent_name" value="<?php echo htmlspecialchars($config['agent_name']); ?>" placeholder="PC-001">
                    <small>Unique name for this agent (e.g., PC-OFFICE-01)</small>
                </div>

                <div class="form-group">
                    <label for="collection_interval">Collection Interval (seconds)</label>
                    <input type="number" id="collection_interval" name="collection_interval" value="<?php echo $config['collection_interval']; ?>" min="5" max="300">
                    <small>How often to collect events (5-300 seconds)</small>
                </div>

                <!-- Save Configuration Button -->
                <input type="hidden" name="action" value="save_config">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Configuration
                </button>
            </form>

            <div class="divider"></div>

            <!-- Test Connection -->
            <form method="POST">
                <h3 style="margin-bottom: 15px; font-size: 16px;">Test Connection</h3>
                <input type="hidden" name="action" value="test_connection">
                <input type="hidden" name="siem_server" value="<?php echo htmlspecialchars($config['siem_server']); ?>">
                <input type="hidden" name="siem_port" value="<?php echo $config['siem_port']; ?>">
                <button type="submit" class="btn btn-secondary" style="width: 100%;">
                    <i class="fas fa-plug"></i> Test Connection to SIEM Server
                </button>
            </form>

            <div class="divider"></div>

            <!-- Agent Control -->
            <h3 style="margin-bottom: 15px; font-size: 16px;">Agent Control</h3>
            <div class="button-group">
                <?php if (!$config['enabled']): ?>
                    <form method="POST" style="grid-column: 1;">
                        <input type="hidden" name="action" value="start_agent">
                        <button type="submit" class="btn btn-success" style="width: 100%;">
                            <i class="fas fa-play"></i> Start Agent
                        </button>
                    </form>
                <?php else: ?>
                    <form method="POST" style="grid-column: 1;">
                        <input type="hidden" name="action" value="stop_agent">
                        <button type="submit" class="btn btn-danger" style="width: 100%;">
                            <i class="fas fa-stop"></i> Stop Agent
                        </button>
                    </form>
                <?php endif; ?>
            </div>

            <!-- Instructions -->
            <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
                <h4 style="margin-bottom: 10px; font-size: 14px;">Quick Start:</h4>
                <ol style="margin-left: 20px; font-size: 13px; line-height: 1.8; color: #666;">
                    <li>Enter your SIEM server IP address</li>
                    <li>Enter your agent name (e.g., PC-OFFICE-01)</li>
                    <li>Click "Save Configuration"</li>
                    <li>Click "Test Connection" to verify</li>
                    <li>Click "Start Agent" to begin collecting events</li>
                    <li>Check your SIEM dashboard for events</li>
                </ol>
            </div>
        </div>
    </div>
</body>
</html>
