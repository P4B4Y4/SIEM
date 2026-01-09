<?php
/**
 * ESET Syslog Listener for JFS SIEM
 * Listens on UDP port 6514 for incoming syslog messages from ESET
 * Run as: php eset-syslog-listener.php
 * Must run with Administrator privileges
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/database.php';

class ESETSyslogListener {
    private $port = 6514;
    private $db;
    private $socket;
    private $running = true;
    private $log_file;
    
    public function __construct() {
        $this->log_file = __DIR__ . '/logs/eset-syslog-listener.log';
        $this->log("=== ESET Syslog Listener Started ===");
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
        $this->log("Creating UDP socket...");
        
        // Create UDP socket
        $this->socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (!$this->socket) {
            $error = socket_strerror(socket_last_error());
            $this->log("✗ Failed to create socket: {$error}");
            throw new Exception("Failed to create socket: {$error}");
        }
        
        $this->log("✓ Socket created");
        
        // Set socket options
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 30, 'usec' => 0]);
        
        // Try to bind to port
        $this->log("Binding to 0.0.0.0:{$this->port}...");
        
        if (!socket_bind($this->socket, '0.0.0.0', $this->port)) {
            $error = socket_strerror(socket_last_error());
            $this->log("✗ Failed to bind to port {$this->port}: {$error}");
            $this->log("⚠ Make sure:");
            $this->log("  1. Running with Administrator privileges");
            $this->log("  2. Port 5514 is not in use (check: netstat -ano | findstr :5514)");
            $this->log("  3. Firewall allows UDP port 5514");
            socket_close($this->socket);
            throw new Exception("Failed to bind to port {$this->port}: {$error}");
        }
        
        $this->log("✓ Listening on 0.0.0.0:{$this->port}");
        $this->log("Waiting for ESET syslog messages...");
        $this->log("Press Ctrl+C to stop\n");
        
        $message_count = 0;
        
        // Listen for messages
        while ($this->running) {
            try {
                $buf = '';
                $from = '';
                $port = 0;
                
                $bytes = @socket_recvfrom($this->socket, $buf, 4096, 0, $from, $port);
                
                if ($bytes === false) {
                    $error_code = socket_last_error($this->socket);
                    // Ignore timeout errors
                    if ($error_code != 10060 && $error_code != SOCKET_EAGAIN && $error_code != SOCKET_EWOULDBLOCK) {
                        $error = socket_strerror($error_code);
                        $this->log("⚠ Socket error: {$error}");
                    }
                    usleep(100000); // 100ms
                    continue;
                }
                
                if ($bytes > 0) {
                    $message_count++;
                    $this->processMessage($buf, $from, $port);
                }
            } catch (Exception $e) {
                $this->log("✗ Error in message loop: " . $e->getMessage());
                $this->log("✓ Listener still running, waiting for next message...");
                usleep(100000);
                continue;
            }
        }
        
        $this->log("Listener stopped after processing {$message_count} messages");
    }
    
    private function processMessage($message, $from_ip, $from_port) {
        try {
            $this->log("Received from {$from_ip}:{$from_port}");
            
            // Parse syslog message
            $parsed = $this->parseSyslog($message);
            
            // Store in database
            $this->storeEvent($parsed, $from_ip, $message);
            
            $this->log("  ✓ Stored in database");
        } catch (Exception $e) {
            $this->log("  ✗ Error processing message: " . $e->getMessage());
        }
    }
    
    private function parseSyslog($message) {
        $parsed = [
            'raw' => $message,
            'timestamp' => date('Y-m-d H:i:s'),
            'severity' => 'medium',
            'hostname' => '',
            'content' => $message
        ];
        
        // Extract priority (e.g., <134>)
        if (preg_match('/^<(\d+)>/', $message, $matches)) {
            $priority = intval($matches[1]);
            $severity = $priority % 8;
            
            $severity_map = [
                0 => 'critical',
                1 => 'critical',
                2 => 'critical',
                3 => 'high',
                4 => 'medium',
                5 => 'medium',
                6 => 'low',
                7 => 'low'
            ];
            
            $parsed['severity'] = $severity_map[$severity] ?? 'medium';
            $message = substr($message, strlen($matches[0]));
        }
        
        // Extract timestamp
        if (preg_match('/^(\w+\s+\d+\s+\d+:\d+:\d+)/', $message, $matches)) {
            // Convert syslog timestamp (e.g., "Dec 09 16:20:00") into SQL DATETIME
            // Syslog timestamps usually omit the year; assume current year.
            $year = date('Y');
            $dt = DateTime::createFromFormat('M d H:i:s Y', $matches[1] . ' ' . $year);
            if ($dt instanceof DateTime) {
                $parsed['timestamp'] = $dt->format('Y-m-d H:i:s');
            }
            $message = substr($message, strlen($matches[0]));
        }
        
        // Extract hostname
        if (preg_match('/^(\S+)\s+/', $message, $matches)) {
            $parsed['hostname'] = $matches[1];
            $message = substr($message, strlen($matches[0]));
        }
        
        $parsed['content'] = $message;
        
        return $parsed;
    }
    
    private function storeEvent($parsed, $from_ip, $raw_message) {
        try {
            if (!$this->db) {
                $this->log("⚠ Database connection lost, reconnecting...");
                $this->db = getDatabase();
            }
            
            // Determine event type and severity
            $event_type = 'ESET-Syslog';
            $severity = $parsed['severity'];
            $content = $parsed['content'];
            $agent_id = 'ESET-' . $from_ip;
            
            // Ensure agent exists
            $this->ensureAgentExists($agent_id, 'ESET', $from_ip);
            
            // Detect threat level from ESET message
            if (preg_match('/virus|malware|ransomware|trojan|worm/i', $content)) {
                $severity = 'critical';
                $event_type = 'ESET-Threat-Detected';
            } elseif (preg_match('/suspicious|potentially unwanted|pua/i', $content)) {
                $severity = 'high';
                $event_type = 'ESET-Suspicious-Activity';
            } elseif (preg_match('/protection disabled|firewall disabled|real-time disabled/i', $content)) {
                $severity = 'critical';
                $event_type = 'ESET-Protection-Disabled';
            } elseif (preg_match('/quarantine|cleaned|removed/i', $content)) {
                $severity = 'medium';
                $event_type = 'ESET-Threat-Remediated';
            }
            
            // Extract IPs if present
            $source_ip = null;
            $dest_ip = null;
            
            if (preg_match('/source[_\s]*ip[=:\s]+(\S+)/i', $content, $m)) {
                $source_ip = $m[1];
            }
            if (preg_match('/destination[_\s]*ip[=:\s]+(\S+)/i', $content, $m)) {
                $dest_ip = $m[1];
            }

            // Extract ports if present
            $source_port = null;
            $dest_port = null;
            if (preg_match('/source[_\s]*port[=:\s]+(\d+)/i', $content, $m)) {
                $source_port = $m[1];
            }
            if (preg_match('/destination[_\s]*port[=:\s]+(\d+)/i', $content, $m)) {
                $dest_port = $m[1];
            }
            
            // Try to insert with agent_id first, fall back to NULL if foreign key fails
            try {
                $stmt = $this->db->prepare("
                    INSERT INTO security_events 
                    (timestamp, event_type, severity, source_ip, dest_ip, source_port, dest_port, raw_log, agent_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");
                
                $stmt->execute([
                    $parsed['timestamp'],
                    $event_type,
                    $severity,
                    $source_ip,
                    $dest_ip,
                    $source_port,
                    $dest_port,
                    $raw_message,
                    $agent_id
                ]);
                
                $this->log("  ✓ Stored in database");
            } catch (Exception $e) {
                // If foreign key fails, try without agent_id
                if (strpos($e->getMessage(), 'foreign key constraint') !== false) {
                    $this->log("  ⚠ Foreign key constraint, storing without agent_id");
                    $stmt = $this->db->prepare("
                        INSERT INTO security_events 
                        (timestamp, event_type, severity, source_ip, dest_ip, source_port, dest_port, raw_log)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ");
                    
                    $stmt->execute([
                        $parsed['timestamp'],
                        $event_type,
                        $severity,
                        $source_ip,
                        $dest_ip,
                        $source_port,
                        $dest_port,
                        $raw_message
                    ]);
                    
                    $this->log("  ✓ Stored in database (without agent_id)");
                } else {
                    throw $e;
                }
            }
            
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
    
    private function ensureAgentExists($agent_id, $agent_type, $agent_ip) {
        try {
            // Check if agent exists
            $stmt = $this->db->prepare("SELECT agent_id FROM agents WHERE agent_id = ?");
            $stmt->execute([$agent_id]);
            
            if ($stmt->rowCount() > 0) {
                return; // Agent already exists
            }
            
            // Try to create agent - use minimal columns
            try {
                $stmt = $this->db->prepare("
                    INSERT INTO agents 
                    (agent_id, agent_type, agent_ip, status, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                ");
                
                $stmt->execute([
                    $agent_id,
                    $agent_type,
                    $agent_ip,
                    'online',
                    date('Y-m-d H:i:s')
                ]);
                
                $this->log("  ✓ Created agent: {$agent_id}");
            } catch (Exception $e) {
                // If columns don't exist, try with just agent_id
                $stmt = $this->db->prepare("INSERT INTO agents (agent_id) VALUES (?)");
                $stmt->execute([$agent_id]);
                $this->log("  ✓ Created agent: {$agent_id}");
            }
            
        } catch (Exception $e) {
            $this->log("  ⚠ Could not create agent: " . $e->getMessage());
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
    $listener = new ESETSyslogListener();
    
    // Keep restarting if it exits unexpectedly
    while (true) {
        try {
            $listener->start();
        } catch (Exception $e) {
            echo "[" . date('Y-m-d H:i:s') . "] Listener crashed: " . $e->getMessage() . "\n";
            echo "[" . date('Y-m-d H:i:s') . "] Restarting in 5 seconds...\n";
            sleep(5);
            $listener = new ESETSyslogListener();
        }
    }
} catch (Exception $e) {
    echo "Failed to start listener: " . $e->getMessage() . "\n";
    exit(1);
}

?>
