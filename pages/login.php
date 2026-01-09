<?php
/**
 * SIEM Login Page
 * With Agent Download Button
 */

session_start();

require_once __DIR__ . '/../config/config.sample.php';
if (file_exists(__DIR__ . '/../config/config.local.php')) {
    require_once __DIR__ . '/../config/config.local.php';
}
require_once __DIR__ . '/../includes/database.php';
require_once __DIR__ . '/../includes/auth.php';

// Check if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    $result = login($username, $password);
    if (is_array($result) && ($result['success'] ?? false) === true) {
        if (!empty($result['mfa_required'])) {
            header('Location: ' . ($result['redirect'] ?? 'mfa-verify.php'));
            exit;
        }
        header('Location: dashboard.php');
        exit;
    }

    $error = is_array($result) ? ($result['message'] ?? 'Invalid username or password') : 'Invalid username or password';
}

// Handle agent download
if (isset($_GET['download']) && $_GET['download'] === 'agent') {
    $agent_file = __DIR__ . '/../dist/JFS_SIEM_Agent_Enhanced_ServiceFix_v28.exe';
    
    if (file_exists($agent_file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="JFS_SIEM_Agent_Enhanced_ServiceFix_v28.exe"');
        header('Content-Length: ' . filesize($agent_file));
        readfile($agent_file);
        exit;
    }

    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Agent installer not found.';
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>JFS ICT Services - SIEM Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .container {
            display: flex;
            width: 90%;
            max-width: 1200px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }
        
        .left-panel {
            flex: 1;
            background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
            color: white;
            padding: 60px 40px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .left-panel h1 {
            font-size: 36px;
            margin-bottom: 20px;
        }
        
        .left-panel p {
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 30px;
            opacity: 0.9;
        }
        
        .features {
            list-style: none;
            margin-bottom: 40px;
        }
        
        .features li {
            padding: 10px 0;
            font-size: 14px;
            display: flex;
            align-items: center;
        }
        
        .features li:before {
            content: "✓";
            margin-right: 10px;
            font-weight: bold;
            font-size: 18px;
        }
        
        .download-btn-left {
            background: white;
            color: #0066cc;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            font-weight: bold;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }
        
        .download-btn-left:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
        
        .right-panel {
            flex: 1;
            padding: 60px 40px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .login-form h2 {
            color: #0066cc;
            margin-bottom: 30px;
            font-size: 28px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #0066cc;
            box-shadow: 0 0 5px rgba(0, 102, 204, 0.3);
        }
        
        .login-btn {
            width: 100%;
            padding: 12px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 5px;
            font-weight: bold;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
            margin-top: 10px;
        }
        
        .login-btn:hover {
            background: #004499;
        }
        
        .error {
            background: #ffebee;
            color: #c62828;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #c62828;
        }
        
        .download-section {
            margin-top: 30px;
            padding-top: 30px;
            border-top: 1px solid #ddd;
        }
        
        .download-section h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 16px;
        }
        
        .download-btn {
            width: 100%;
            padding: 12px;
            background: #00cc66;
            color: white;
            border: none;
            border-radius: 5px;
            font-weight: bold;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
            text-decoration: none;
            display: block;
            text-align: center;
        }
        
        .download-btn:hover {
            background: #009944;
        }
        
        @media (max-width: 768px) {
            .container {
                flex-direction: column;
            }
            
            .left-panel {
                padding: 40px 30px;
            }
            
            .right-panel {
                padding: 40px 30px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Left Panel -->
        <div class="left-panel">
            <h1>JFS ICT Services</h1>
            <h2 style="font-size: 24px; margin-bottom: 30px;">SIEM System</h2>
            <p>Professional Security Event Management & Remote Access Control</p>
            
            <ul class="features">
                <li>Real-time event collection</li>
                <li>Remote PC control</li>
                <li>Screenshot capture</li>
                <li>Command execution</li>
                <li>24/7 monitoring</li>
                <li>Automatic persistence</li>
            </ul>
            
            <a href="?download=agent" class="download-btn-left">
                📥 Download Agent
            </a>
        </div>
        
        <!-- Right Panel -->
        <div class="right-panel">
            <div class="login-form">
                <h2>Login</h2>
                
                <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required autofocus>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit" class="login-btn">Login</button>
                </form>
                
                <div class="download-section">
                    <h3>📥 Download Agent</h3>
                    <p style="font-size: 13px; color: #666; margin-bottom: 10px;">
                        Deploy the SIEM Agent to remote PCs for event collection and remote access.
                    </p>
                    <a href="?download=agent" class="download-btn">
                        Download JFS_SIEM_Agent_Enhanced_ServiceFix_v28.exe
                    </a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
