<?php
/**
 * Agent Events Listener for JFS SIEM
 * Listens on TCP port 80 for incoming agent events (HTTP)
 * Agents send events via HTTP POST to this listener
 * Run as: php agent-events-listener.php
 * Must run with Administrator privileges
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/database.php';

class AgentEventsListener {
    private $port = 80;
    private $db;
    private $socket;
    private $running = true;
    private $log_file;
    private $max_clients = 10;
    
    public function __construct() {
        $this->log_file = __DIR__ . '/logs/agent-events-listener.log';
        $this->log("=== Agent Events Listener Started ===");
        $this->log("Port: {$this->port}");
        $this->log("Time: " . date('Y-m-d H:i:s'));
        
        try {
            $this->db = getDatabase();
            $this->log("✓ Database connected");
        } catch (Exception $e) {
            $this->log("✗ Database connection failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    private function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $msg = "[{$timestamp}] {$message}";
        echo $msg . "\n";
        file_put_contents($this->log_file, $msg . "\n", FILE_APPEND);
    }
    
    public function start() {
        $this->log("Creating TCP socket...");
        
        // Create TCP socket
        $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if (!$this->socket) {
            $error = socket_strerror(socket_last_error());
            $this->log("✗ Failed to create socket: {$error}");
            throw new Exception("Failed to create socket: {$error}");
        }
        
        $this->log("✓ Socket created");
        
        // Set socket options
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
        
        // Try to bind to port
        $this->log("Binding to 0.0.0.0:{$this->port}...");
        
        if (!socket_bind($this->socket, '0.0.0.0', $this->port)) {
            $error = socket_strerror(socket_last_error());
            $this->log("✗ Failed to bind to port {$this->port}: {$error}");
            $this->log("⚠ Make sure:");
            $this->log("  1. Running with Administrator privileges");
            $this->log("  2. Port 80 is not in use (check: netstat -ano | findstr :80)");
            $this->log("  3. Firewall allows TCP port 80");
            socket_close($this->socket);
            throw new Exception("Failed to bind to port {$this->port}: {$error}");
        }
        
        $this->log("✓ Listening on 0.0.0.0:{$this->port}");
        
        // Listen for connections
        if (!socket_listen($this->socket, $this->max_clients)) {
            $error = socket_strerror(socket_last_error());
            $this->log("✗ Failed to listen: {$error}");
            socket_close($this->socket);
            throw new Exception("Failed to listen: {$error}");
        }
        
        $this->log("✓ Listening for agent connections...");
        $this->log("Press Ctrl+C to stop\n");
        
        // Accept connections
        while ($this->running) {
            try {
                $client = @socket_accept($this->socket);
                
                if ($client === false) {
                    $error_code = socket_last_error($this->socket);
                    // Ignore timeout errors
                    if ($error_code != 10060 && $error_code != SOCKET_EAGAIN && $error_code != SOCKET_EWOULDBLOCK) {
                        $error = socket_strerror($error_code);
                        $this->log("⚠ Socket error: {$error}");
                    }
                    usleep(100000);
                    continue;
                }
                
                // Handle client in a separate process/thread
                $this->handleClient($client);
                socket_close($client);
                
            } catch (Exception $e) {
                $this->log("✗ Error: " . $e->getMessage());
                usleep(100000);
            }
        }
    }
    
    private function handleClient($client) {
        try {
            // Get client IP
            socket_getpeername($client, $client_ip, $client_port);
            $this->log("Connection from {$client_ip}:{$client_port}");
            
            // Read HTTP request
            $request = '';
            while (true) {
                $chunk = @socket_read($client, 4096);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $request .= $chunk;
                if (strpos($request, "\r\n\r\n") !== false) {
                    break;
                }
            }
            
            if (empty($request)) {
                $this->log("  ✗ Empty request");
                return;
            }
            
            // Parse HTTP request
            $lines = explode("\r\n", $request);
            $request_line = $lines[0];
            
            // Extract method, path, and HTTP version
            list($method, $path, $http_version) = explode(' ', $request_line);
            
            $this->log("  Method: {$method}, Path: {$path}");
            
            // Extract headers and body
            $headers = [];
            $body = '';
            $body_start = false;
            
            foreach ($lines as $line) {
                if ($line === '') {
                    $body_start = true;
                    continue;
                }
                
                if (!$body_start) {
                    if (strpos($line, ':') !== false) {
                        list($key, $value) = explode(':', $line, 2);
                        $headers[trim($key)] = trim($value);
                    }
                } else {
                    $body .= $line;
                }
            }
            
            // Handle POST requests with JSON data
            if ($method === 'POST' && !empty($body)) {
                $this->processAgentEvent($body, $client_ip, $headers);
            }
            
            // Send HTTP response
            $response = "HTTP/1.1 200 OK\r\n";
            $response .= "Content-Type: application/json\r\n";
            $response .= "Content-Length: 27\r\n";
            $response .= "Connection: close\r\n";
            $response .= "\r\n";
            $response .= '{"status":"received","ok":true}';
            
            socket_write($client, $response);
            
        } catch (Exception $e) {
            $this->log("  ✗ Error handling client: " . $e->getMessage());
        }
    }
    
    private function processAgentEvent($body, $client_ip, $headers) {
        try {
            // Try to parse JSON
            $data = json_decode($body, true);
            
            if (!is_array($data)) {
                $this->log("  ✗ Invalid JSON data");
                return;
            }
            
            $this->log("  ✓ Received agent event from {$client_ip}");
            
            // Extract event details
            $event_type = $data['event_type'] ?? 'Agent-Event';
            $severity = $data['severity'] ?? 'medium';
            $agent_id = $data['agent_id'] ?? 'Agent-' . $client_ip;
            $pc_name = $data['pc_name'] ?? 'Unknown';
            $source_ip = $data['source_ip'] ?? $client_ip;
            $destination_ip = $data['destination_ip'] ?? null;
            $source_port = $data['source_port'] ?? null;
            $destination_port = $data['destination_port'] ?? null;
            $message = $data['message'] ?? '';
            
            // Store in database
            $this->storeEvent([
                'event_type' => $event_type,
                'severity' => $severity,
                'agent_id' => $agent_id,
                'pc_name' => $pc_name,
                'source_ip' => $source_ip,
                'destination_ip' => $destination_ip,
                'source_port' => $source_port,
                'destination_port' => $destination_port,
                'message' => $message,
                'raw_log' => $body
            ]);
            
            $this->log("  ✓ Stored in database");
            
        } catch (Exception $e) {
            $this->log("  ✗ Error processing agent event: " . $e->getMessage());
        }
    }
    
    private function storeEvent($event) {
        try {
            if (!$this->db) {
                $this->log("⚠ Database connection lost, reconnecting...");
                $this->db = getDatabase();
            }
            
            // Insert into database
            $stmt = $this->db->prepare("
                INSERT INTO security_events 
                (event_type, severity, source_ip, destination_ip, source_port, destination_port, raw_log, event_timestamp, agent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $event['event_type'],
                $event['severity'],
                $event['source_ip'],
                $event['destination_ip'],
                $event['source_port'],
                $event['destination_port'],
                $event['raw_log'],
                date('Y-m-d H:i:s'),
                $event['agent_id']
            ]);
            
        } catch (Exception $e) {
            $this->log("⚠ Database error: " . $e->getMessage());
            
            // Try to reconnect
            try {
                $this->db = getDatabase();
            } catch (Exception $e2) {
                $this->log("✗ Reconnection failed: " . $e2->getMessage());
            }
        }
    }
    
    public function stop() {
        $this->running = false;
        if ($this->socket) {
            socket_close($this->socket);
        }
        $this->log("Listener stopped");
    }
}

// Handle Ctrl+C gracefully
if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGTERM, function() {
        global $listener;
        echo "\n\nShutting down...\n";
        if (isset($listener)) {
            $listener->stop();
        }
        exit(0);
    });
}

// Start listener
try {
    $listener = new AgentEventsListener();
    $listener->start();
} catch (Exception $e) {
    echo "Failed to start listener: " . $e->getMessage() . "\n";
    exit(1);
}

?>
