<?php
/**
 * Agent Download Page
 * Allows users to download the SIEM agent without login
 */

// Check if download is requested
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    
    // Only allow downloading the agent EXE
    if ($file === 'agent') {
        $agent_file = __DIR__ . '/JFS_SIEM_Agent.exe';
        
        if (file_exists($agent_file)) {
            // Set headers for download
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="JFS_SIEM_Agent.exe"');
            header('Content-Length: ' . filesize($agent_file));
            header('Pragma: no-cache');
            header('Expires: 0');
            
            // Read and output file
            readfile($agent_file);
            exit;
        } else {
            http_response_code(404);
            die('Agent file not found. Please contact your administrator.');
        }
    }
}

// If no download requested, show download page
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Download Agent - <?php echo isset($_SERVER['HTTP_HOST']) ? 'SIEM' : 'Agent'; ?></title>
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
            padding: 40px;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .header i {
            color: #667eea;
            font-size: 48px;
            margin-bottom: 15px;
        }

        .header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 5px;
        }

        .header p {
            color: #666;
            font-size: 14px;
        }

        .info-box {
            background: #e7f5ff;
            border-left: 4px solid #1971c2;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 13px;
            color: #1971c2;
            line-height: 1.6;
        }

        .features {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
        }

        .features h3 {
            font-size: 14px;
            margin-bottom: 12px;
            color: #333;
        }

        .features ul {
            list-style: none;
            margin-left: 0;
        }

        .features li {
            padding: 6px 0;
            font-size: 13px;
            color: #666;
        }

        .features li:before {
            content: "✓ ";
            color: #51cf66;
            font-weight: bold;
            margin-right: 8px;
        }

        .download-section {
            text-align: center;
            margin-bottom: 25px;
        }

        .btn-download {
            display: inline-block;
            padding: 15px 40px;
            background: #51cf66;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
            border: none;
            cursor: pointer;
        }

        .btn-download:hover {
            background: #40c057;
            transform: translateY(-3px);
            box-shadow: 0 10px 25px rgba(81, 207, 102, 0.3);
        }

        .file-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 13px;
            color: #666;
        }

        .file-info strong {
            color: #333;
        }

        .instructions {
            background: #fff3e0;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            border-radius: 8px;
            font-size: 13px;
            color: #92400e;
            line-height: 1.6;
        }

        .instructions h4 {
            margin-bottom: 10px;
            color: #b45309;
        }

        .instructions ol {
            margin-left: 20px;
        }

        .instructions li {
            margin-bottom: 6px;
        }

        .back-link {
            text-align: center;
            margin-top: 25px;
        }

        .back-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
        }

        .back-link a:hover {
            text-decoration: underline;
        }

        @media (max-width: 600px) {
            .container {
                padding: 25px;
            }

            .header h1 {
                font-size: 24px;
            }

            .btn-download {
                padding: 12px 30px;
                font-size: 13px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <i class="fas fa-robot"></i>
            <h1>Download SIEM Agent</h1>
            <p>Professional Windows agent for event collection</p>
        </div>

        <div class="info-box">
            <i class="fas fa-info-circle"></i>
            <strong>No login required!</strong> Download the agent directly and deploy it to your remote PCs.
        </div>

        <div class="features">
            <h3><i class="fas fa-check-circle"></i> Agent Features</h3>
            <ul>
                <li>Modern Windows GUI interface</li>
                <li>Automatic Windows Event Log collection</li>
                <li>Secure connection to SIEM server</li>
                <li>Built-in connection testing</li>
                <li>Runs as Windows Service</li>
                <li>Auto-starts on system boot</li>
                <li>Auto-restarts on crash</li>
                <li>Real-time status display</li>
            </ul>
        </div>

        <div class="file-info">
            <strong>File Information:</strong><br>
            Name: JFS_SIEM_Agent.exe<br>
            Size: 10.8 MB<br>
            Type: Windows Executable<br>
            Requirements: Windows 7 or later
        </div>

        <div class="download-section">
            <a href="?file=agent" class="btn-download">
                <i class="fas fa-download"></i> Download Agent (10.8 MB)
            </a>
        </div>

        <div class="instructions">
            <h4><i class="fas fa-tasks"></i> Quick Setup (3 Steps)</h4>
            <ol>
                <li><strong>Copy</strong> the downloaded EXE to your remote PC</li>
                <li><strong>Run</strong> the EXE by double-clicking it</li>
                <li><strong>Configure</strong> with your SIEM server IP and click "Install Service"</li>
            </ol>
        </div>

        <div class="back-link">
            <a href="../pages/login.php">
                <i class="fas fa-arrow-left"></i> Back to Login
            </a>
        </div>
    </div>
</body>
</html>
