<?php
/**
 * SIEM Remote Access API
 * Handles remote PC access requests
 */

header('Content-Type: application/json');

require_once __DIR__ . '/../config/config.php';

ini_set('display_errors', 0);
error_reporting(0);

$action = $_GET['action'] ?? '';
$agent_id = $_GET['agent'] ?? '';

// Database connection
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);

if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

switch ($action) {
    case 'get_agents':
        get_agents($db);
        break;
    
    case 'get_agent_details':
        get_agent_details($db, $agent_id);
        break;
    
    case 'send_command':
        send_command($db, $agent_id);
        break;
    
    case 'send_bulk_commands':
        send_bulk_commands($db);
        break;
    
    case 'get_screen':
        get_screen($db, $agent_id);
        break;
    
    case 'mouse_move':
        mouse_move($db, $agent_id);
        break;
    
    case 'mouse_click':
        mouse_click($db, $agent_id);
        break;
    
    case 'keyboard_input':
        keyboard_input($db, $agent_id);
        break;
    
    case 'get_pending_commands':
        get_pending_commands($db, $agent_id);
        break;
    
    case 'report_command':
        report_command($db);
        break;
    
    case 'get_command_results':
        get_command_results($db, $agent_id);
        break;
    
    case 'get_command_output':
        get_command_output($db, $agent_id);
        break;
    
    case 'debug_commands':
        debug_commands($db, $agent_id);
        break;
    
    case 'get_command_result':
        get_command_result($db);
        break;
    
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
}

$db->close();

function get_agents($db) {
    /**
     * Get list of all connected agents
     */
    $result = $db->query("
        SELECT source_ip as agent_name,
               MAX(timestamp) as last_seen,
               COUNT(*) as event_count,
               MAX(agent_id) as agent_id,
               MAX(CASE WHEN source_ip REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' THEN source_ip ELSE NULL END) as ip
        FROM security_events
        WHERE source_ip IS NOT NULL AND source_ip != 'unknown'
        GROUP BY source_ip
        ORDER BY last_seen DESC
    ");
    
    $agents = [];
    while ($row = $result->fetch_assoc()) {
        $agents[] = [
            'name' => $row['agent_name'],
            'last_seen' => $row['last_seen'],
            'events' => $row['event_count'],
            'status' => strtotime($row['last_seen']) > time() - 300 ? 'online' : 'offline',
            'agent_id' => $row['agent_id'] ?? null,
            'ip' => $row['ip'] ?? null
        ];
    }
    
    echo json_encode(['agents' => $agents]);
}

function get_agent_details($db, $agent_id) {
    /**
     * Get detailed info about specific agent
     */
    $stmt = $db->prepare("
        SELECT user_account, source_ip, MAX(timestamp) as last_seen, COUNT(*) as event_count
        FROM security_events
        WHERE user_account = ?
        GROUP BY user_account
    ");
    
    $stmt->bind_param("s", $agent_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $agent = $result->fetch_assoc();
    
    if ($agent) {
        echo json_encode([
            'agent' => $agent['user_account'],
            'ip' => $agent['source_ip'],
            'last_seen' => $agent['last_seen'],
            'events' => $agent['event_count'],
            'status' => strtotime($agent['last_seen']) > time() - 300 ? 'online' : 'offline'
        ]);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Agent not found']);
    }
    
    $stmt->close();
}

function send_command($db, $agent_id) {
    /**
     * Send command to agent for execution
     */
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    $command = $data['command'] ?? '';
    
    // Log what we received
    error_log("send_command: agent=$agent_id, command='$command', raw_input=$input");
    
    if (!$command) {
        http_response_code(400);
        echo json_encode(['error' => 'No command provided']);
        return;
    }
    
    // Store command in database for agent to retrieve
    $stmt = $db->prepare("
        INSERT INTO remote_commands (agent_name, command, timestamp, status)
        VALUES (?, ?, NOW(), 'pending')
    ");
    
    $stmt->bind_param("ss", $agent_id, $command);
    
    if ($stmt->execute()) {
        echo json_encode(['status' => 'ok', 'message' => 'Command sent']);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to send command']);
    }
    
    $stmt->close();
}

 function send_bulk_commands($db) {
     /**
      * Send the same command to multiple agents
      * Expected JSON body: {"agents": ["PC1", "PC2"], "command": "whoami"}
      */
     $input = file_get_contents('php://input');
     $data = json_decode($input, true);

     $command = $data['command'] ?? '';
     $agents = $data['agents'] ?? [];

     if (!$command) {
         http_response_code(400);
         echo json_encode(['error' => 'No command provided']);
         return;
     }

     if (!is_array($agents) || count($agents) === 0) {
         http_response_code(400);
         echo json_encode(['error' => 'No agents provided']);
         return;
     }

     $agents = array_values(array_unique(array_filter(array_map('strval', $agents), function ($a) {
         return trim($a) !== '';
     })));

     $max_agents = 100;
     if (count($agents) > $max_agents) {
         http_response_code(400);
         echo json_encode(['error' => 'Too many agents selected', 'max_agents' => $max_agents]);
         return;
     }

     $stmt = $db->prepare("
         INSERT INTO remote_commands (agent_name, command, timestamp, status)
         VALUES (?, ?, NOW(), 'pending')
     ");

     if (!$stmt) {
         http_response_code(500);
         echo json_encode(['error' => 'Database error: ' . $db->error]);
         return;
     }

     $results = [];
     $ok_count = 0;

     foreach ($agents as $agent) {
         $agent_trim = trim($agent);
         if ($agent_trim === '') {
             continue;
         }

         $stmt->bind_param('ss', $agent_trim, $command);
         $exec_ok = $stmt->execute();

         if ($exec_ok) {
             $ok_count++;
             $results[] = ['agent' => $agent_trim, 'status' => 'ok', 'command_id' => $stmt->insert_id];
         } else {
             $results[] = ['agent' => $agent_trim, 'status' => 'error', 'error' => 'Failed to send command'];
         }
     }

     $stmt->close();
     echo json_encode([
         'status' => 'ok',
         'queued' => $ok_count,
         'total' => count($agents),
         'results' => $results
     ]);
 }

function get_screen($db, $agent_id) {
    /**
     * Get latest screenshot from agent
     */
    try {
        $stmt = $db->prepare("
            SELECT screenshot, timestamp 
            FROM security_events
            WHERE user_account = ? AND event_type = 'screenshot'
            ORDER BY timestamp DESC
            LIMIT 1
        ");
        
        $stmt->bind_param("s", $agent_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        
        if ($row && $row['screenshot']) {
            // Extract base64 from event_data JSON
            $event_data = json_decode($row['event_data'], true);
            echo json_encode([
                'status' => 'success',
                'screenshot' => $event_data['screenshot'] ?? '',
                'timestamp' => $row['timestamp'],
                'agent' => $agent_id
            ]);
        } else {
            echo json_encode([
                'status' => 'pending',
                'message' => 'No screenshot available yet',
                'agent' => $agent_id
            ]);
        }
        
        $stmt->close();
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to retrieve screenshot: ' . $e->getMessage()]);
    }
}

function mouse_move($db, $agent_id) {
    /**
     * Move mouse on remote PC
     */
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    $x = $data['x'] ?? 0;
    $y = $data['y'] ?? 0;
    
    // Store mouse movement command
    $command = json_encode(['action' => 'mouse_move', 'x' => $x, 'y' => $y]);
    
    $stmt = $db->prepare("
        INSERT INTO remote_commands (agent_name, command, timestamp, status)
        VALUES (?, ?, NOW(), 'pending')
    ");
    
    $stmt->bind_param("ss", $agent_id, $command);
    $stmt->execute();
    
    echo json_encode(['status' => 'ok', 'x' => $x, 'y' => $y]);
    $stmt->close();
}

function mouse_click($db, $agent_id) {
    /**
     * Click mouse on remote PC
     */
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    $button = $data['button'] ?? 'left';
    $x = $data['x'] ?? 0;
    $y = $data['y'] ?? 0;
    
    $command = json_encode(['action' => 'mouse_click', 'button' => $button, 'x' => $x, 'y' => $y]);
    
    $stmt = $db->prepare("
        INSERT INTO remote_commands (agent_name, command, timestamp, status)
        VALUES (?, ?, NOW(), 'pending')
    ");
    
    $stmt->bind_param("ss", $agent_id, $command);
    $stmt->execute();
    
    echo json_encode(['status' => 'ok', 'button' => $button]);
    $stmt->close();
}

function keyboard_input($db, $agent_id) {
    /**
     * Send keyboard input to remote PC
     */
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    $keys = $data['keys'] ?? '';
    
    if (!$keys) {
        http_response_code(400);
        echo json_encode(['error' => 'No keys provided']);
        return;
    }
    
    $command = json_encode(['action' => 'keyboard_input', 'keys' => $keys]);
    
    $stmt = $db->prepare("
        INSERT INTO remote_commands (agent_name, command, timestamp, status)
        VALUES (?, ?, NOW(), 'pending')
    ");
    
    $stmt->bind_param("ss", $agent_id, $command);
    $stmt->execute();
    
    echo json_encode(['status' => 'ok', 'keys' => $keys]);
    $stmt->close();
}

function get_pending_commands($db, $agent_id) {
    /**
     * Get pending commands for agent
     */
    // Try exact match first, then try case-insensitive
    $stmt = $db->prepare("
        SELECT id, command FROM remote_commands
        WHERE (agent_name = ? OR LOWER(agent_name) = LOWER(?)) AND status = 'pending'
        ORDER BY timestamp ASC
        LIMIT 10
    ");
    
    $stmt->bind_param("ss", $agent_id, $agent_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $commands = [];
    while ($row = $result->fetch_assoc()) {
        $commands[] = [
            'id' => $row['id'],
            'command' => $row['command']
        ];
    }
    
    echo json_encode(['commands' => $commands]);
    $stmt->close();
}

function report_command($db) {
    /**
     * Report command execution result
     */
    $cmd_id = intval($_GET['id'] ?? 0);
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    $status = $data['result'] ?? 'success';  // 'success' or 'failed' or 'error'
    $result = $data['result'] ?? 'success';  // Same as status for now
    $output = $data['output'] ?? '';
    $error = $data['error'] ?? '';
    
    if (!$cmd_id) {
        http_response_code(400);
        echo json_encode(['error' => 'No command ID provided']);
        return;
    }
    
    $stmt = $db->prepare("
        UPDATE remote_commands
        SET status = ?, result = ?, output = ?, error = ?, completed_at = NOW()
        WHERE id = ?
    ");
    
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $db->error]);
        return;
    }
    
    $stmt->bind_param("ssssi", $status, $result, $output, $error, $cmd_id);
    
    if ($stmt->execute()) {
        echo json_encode(['status' => 'ok', 'updated' => $stmt->affected_rows]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update command: ' . $stmt->error]);
    }
    
    $stmt->close();
}

function get_command_results($db, $agent_id) {
    /**
     * Get command results from database
     */
    $stmt = $db->prepare("
        SELECT id, command, output, error, status, completed_at
        FROM remote_commands
        WHERE (agent_name = ? OR LOWER(agent_name) = LOWER(?))
        AND status IN ('completed', 'failed', 'success', 'error')
        ORDER BY completed_at DESC
        LIMIT 50
    ");
    
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $db->error]);
        return;
    }
    
    $stmt->bind_param("ss", $agent_id, $agent_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $commands = [];
    while ($row = $result->fetch_assoc()) {
        $commands[] = [
            'id' => $row['id'],
            'command' => $row['command'],
            'output' => $row['output'] ?? '',
            'error' => $row['error'] ?? '',
            'status' => $row['status'],
            'completed_at' => $row['completed_at']
        ];
    }
    
    echo json_encode([
        'status' => 'ok',
        'commands' => $commands,
        'count' => count($commands)
    ]);
    $stmt->close();
}

function get_command_output($db, $agent_id) {
    /**
     * Get latest command output for terminal display
     */
    $cmd_id = $_GET['cmd_id'] ?? '';
    
    $stmt = $db->prepare("
        SELECT command, status, output, error, timestamp, completed_at
        FROM remote_commands
        WHERE id = ? AND agent_name = ?
    ");
    
    $stmt->bind_param("is", $cmd_id, $agent_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    
    if ($row) {
        echo json_encode([
            'id' => $cmd_id,
            'command' => $row['command'],
            'status' => $row['status'],
            'output' => $row['output'],
            'error' => $row['error'],
            'timestamp' => $row['timestamp'],
            'completed_at' => $row['completed_at']
        ]);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Command not found']);
    }
    
    $stmt->close();
}

function debug_commands($db, $agent_id) {
    /**
     * Debug: Show all commands for agent (for troubleshooting)
     */
    // Show all commands for this agent
    $stmt = $db->prepare("
        SELECT id, agent_name, command, status, timestamp
        FROM remote_commands
        WHERE agent_name = ? OR LOWER(agent_name) = LOWER(?)
        ORDER BY timestamp DESC
        LIMIT 20
    ");
    
    $stmt->bind_param("ss", $agent_id, $agent_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $commands = [];
    while ($row = $result->fetch_assoc()) {
        $commands[] = $row;
    }
    
    // Also show what agent names exist in database
    $all_agents = $db->query("
        SELECT DISTINCT agent_name FROM remote_commands ORDER BY agent_name
    ");
    
    $agent_names = [];
    while ($row = $all_agents->fetch_assoc()) {
        $agent_names[] = $row['agent_name'];
    }
    
    echo json_encode([
        'requested_agent' => $agent_id,
        'commands_found' => count($commands),
        'commands' => $commands,
        'all_agent_names_in_db' => $agent_names
    ]);
    
    $stmt->close();
}

function get_command_result($db) {
    /**
     * Get result of a specific command by ID
     */
    $command_id = intval($_GET['command_id'] ?? 0);
    
    if (!$command_id) {
        http_response_code(400);
        echo json_encode(['error' => 'No command ID provided']);
        return;
    }
    
    $stmt = $db->prepare("
        SELECT id, command, status, output, error, timestamp, completed_at
        FROM remote_commands
        WHERE id = ?
    ");
    
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $db->error]);
        return;
    }
    
    $stmt->bind_param("i", $command_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    
    if ($row) {
        echo json_encode([
            'id' => $row['id'],
            'command' => $row['command'],
            'status' => $row['status'],
            'output' => $row['output'] ?? '',
            'error' => $row['error'] ?? '',
            'timestamp' => $row['timestamp'],
            'completed_at' => $row['completed_at']
        ]);
    } else {
        http_response_code(404);
        echo json_encode(['status' => 'pending', 'error' => 'Command not found or still pending']);
    }
    
    $stmt->close();
}

?>
