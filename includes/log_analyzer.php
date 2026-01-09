<?php
/**
 * Rule-Based Log Analyzer
 * 
 * Classifies, scores, and analyzes logs using fixed rules
 * Produces structured JSON output for SIEM dashboard
 */

class LogAnalyzer {
    
    // Category keywords
    private $category_rules = [
        'Authentication' => [
            'login', 'logon', 'credential', 'token', 'authentication',
            'ntlm', 'kerberos', 'failed login', 'logoff', 'password',
            'user account', 'access denied', 'invalid credentials'
        ],
        'Process Creation' => [
            'process', 'pid', 'cmd', 'command line', 'started', 'spawned',
            'executable', 'launch', 'create process', 'image name',
            'parent process', 'child process'
        ],
        'Network Connection' => [
            'connection', 'tcp', 'udp', 'firewall', 'port', 'ip address',
            'network', 'socket', 'dns', 'http', 'https', 'packet',
            'source ip', 'destination', 'protocol', 'established'
        ],
        'File Access' => [
            'file', 'read', 'write', 'delete', 'modified', '.exe', '.dll',
            'directory', 'folder', 'path', 'access', 'permission',
            'created', 'renamed', 'copied', 'moved'
        ],
        'System Error' => [
            'error', 'warning', 'crash', 'failed', 'exception',
            'fatal', 'critical', 'failure', 'fault', 'issue',
            'problem', 'stopped', 'timeout'
        ],
        'Malware or Suspicious Activity' => [
            'powershell', 'base64', 'encoded', 'temp', 'unknown process',
            'privilege', 'escalation', 'injection', 'shellcode',
            'obfuscated', 'suspicious', 'malware', 'trojan', 'ransomware',
            'backdoor', 'persistence', 'lateral movement'
        ]
    ];
    
    // Severity scoring rules
    private $severity_keywords = [
        'critical' => [
            'privilege escalation', 'persistence', 'malware', 'ransomware',
            'backdoor', 'lateral movement', 'data exfiltration',
            'unauthorized access', 'system compromise'
        ],
        'high' => [
            'base64', 'encoded', 'powershell', 'cmd.exe', 'suspicious process',
            'unknown process', 'rare port', 'new ip', 'failed login',
            'injection', 'shellcode', 'obfuscated'
        ],
        'medium' => [
            'repeated command', 'unusual ip', 'failed attempt', 'warning',
            'error', 'access denied', 'permission denied'
        ],
        'low' => [
            'normal operation', 'routine', 'expected', 'standard'
        ]
    ];
    
    // Anomaly detection rules
    private $anomaly_rules = [
        'repeated_event' => 5,  // Mark as anomaly if event repeats > 5 times
        'rare_port_threshold' => 50000,  // Ports > 50000 are rare
    ];
    
    private $db;
    private $event_cache = [];
    
    public function __construct($database = null) {
        $this->db = $database;
    }
    
    /**
     * Main analysis function
     * 
     * @param array $log Log entry to analyze
     * @return array Structured analysis result
     */
    public function analyze($log) {
        // Extract text content
        $text = $this->extract_text($log);
        $text_lower = strtolower($text);
        
        // Determine category
        $category = $this->detect_category($text_lower);
        
        // Calculate severity (1-10)
        $severity = $this->calculate_severity($text_lower, $category);
        
        // Check for anomalies
        $anomaly = $this->detect_anomaly($log, $text_lower);
        
        // Generate reason
        $reason = $this->generate_reason($text_lower, $category, $severity);
        
        // Generate recommendation
        $recommendation = $this->generate_recommendation($category, $severity, $anomaly);
        
        return [
            'category' => $category,
            'severity' => (string)$severity,
            'anomaly' => $anomaly ? 'Yes' : 'No',
            'reason' => $reason,
            'recommendation' => $recommendation
        ];
    }
    
    /**
     * Extract text from log entry
     */
    private function extract_text($log) {
        if (is_array($log)) {
            $parts = [];
            foreach ($log as $key => $value) {
                if (is_string($value)) {
                    $parts[] = $value;
                } elseif (is_array($value)) {
                    $parts[] = json_encode($value);
                }
            }
            return implode(' ', $parts);
        }
        return (string)$log;
    }
    
    /**
     * Detect log category based on keywords
     */
    private function detect_category($text_lower) {
        $scores = [];
        
        foreach ($this->category_rules as $category => $keywords) {
            $score = 0;
            foreach ($keywords as $keyword) {
                if (strpos($text_lower, strtolower($keyword)) !== false) {
                    $score++;
                }
            }
            $scores[$category] = $score;
        }
        
        // Return category with highest score
        if (max($scores) > 0) {
            return array_search(max($scores), $scores);
        }
        
        return 'System Event';
    }
    
    /**
     * Calculate severity score (1-10)
     */
    private function calculate_severity($text_lower, $category) {
        $severity = 1;  // Default: low
        
        // Check for critical keywords
        foreach ($this->severity_keywords['critical'] as $keyword) {
            if (strpos($text_lower, strtolower($keyword)) !== false) {
                return 10;  // Critical
            }
        }
        
        // Check for high severity keywords
        foreach ($this->severity_keywords['high'] as $keyword) {
            if (strpos($text_lower, strtolower($keyword)) !== false) {
                $severity = max($severity, 8);
            }
        }
        
        // Check for medium severity keywords
        foreach ($this->severity_keywords['medium'] as $keyword) {
            if (strpos($text_lower, strtolower($keyword)) !== false) {
                $severity = max($severity, 5);
            }
        }
        
        // Category-based severity adjustments
        switch ($category) {
            case 'Malware or Suspicious Activity':
                $severity = max($severity, 8);
                break;
            case 'Process Creation':
                if (strpos($text_lower, 'powershell') !== false || 
                    strpos($text_lower, 'cmd.exe') !== false) {
                    $severity = max($severity, 7);
                }
                break;
            case 'Network Connection':
                if (preg_match('/port\s*[>:]\s*(\d+)/', $text_lower, $matches)) {
                    if ($matches[1] > 50000) {
                        $severity = max($severity, 6);
                    }
                }
                break;
            case 'File Access':
                if (strpos($text_lower, 'system32') !== false || 
                    strpos($text_lower, 'windows') !== false ||
                    strpos($text_lower, 'program files') !== false) {
                    $severity = max($severity, 6);
                }
                break;
            case 'System Error':
                if (strpos($text_lower, 'critical') !== false) {
                    $severity = max($severity, 7);
                }
                break;
        }
        
        return min($severity, 10);  // Cap at 10
    }
    
    /**
     * Detect anomalies
     */
    private function detect_anomaly($log, $text_lower) {
        // Check for repeated events
        if ($this->is_repeated_event($log)) {
            return true;
        }
        
        // Check for unseen process name
        if ($this->is_unseen_process($log)) {
            return true;
        }
        
        // Check for rare port
        if ($this->has_rare_port($text_lower)) {
            return true;
        }
        
        // Check for login from new IP
        if ($this->is_new_ip($log)) {
            return true;
        }
        
        // Check for file activity in system directories
        if ($this->is_system_directory_access($text_lower)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if event is repeated (> 5 times)
     */
    private function is_repeated_event($log) {
        if (!$this->db) {
            return false;
        }
        
        try {
            $event_id = $log['event_id'] ?? null;
            $computer = $log['computer'] ?? null;
            
            if (!$event_id || !$computer) {
                return false;
            }
            
            // Check if same event occurred > 5 times in last hour
            $query = "SELECT COUNT(*) as count FROM security_events 
                     WHERE event_id = ? AND computer = ? 
                     AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)";
            
            $stmt = $this->db->prepare($query);
            $stmt->bind_param('ss', $event_id, $computer);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            return $row['count'] > 5;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Check for unseen process name
     */
    private function is_unseen_process($log) {
        if (!$this->db) {
            return false;
        }
        
        try {
            $process_name = $log['process_name'] ?? null;
            
            if (!$process_name) {
                return false;
            }
            
            // Check if process name has been seen before
            $query = "SELECT COUNT(*) as count FROM security_events 
                     WHERE process_name = ?";
            
            $stmt = $this->db->prepare($query);
            $stmt->bind_param('s', $process_name);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            return $row['count'] == 0;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Check for rare port (> 50000)
     */
    private function has_rare_port($text_lower) {
        // Look for port numbers > 50000
        if (preg_match('/port\s*[>:]\s*(\d+)/', $text_lower, $matches)) {
            return (int)$matches[1] > $this->anomaly_rules['rare_port_threshold'];
        }
        
        // Look for IP:PORT patterns
        if (preg_match('/\d+\.\d+\.\d+\.\d+:(\d+)/', $text_lower, $matches)) {
            return (int)$matches[1] > $this->anomaly_rules['rare_port_threshold'];
        }
        
        return false;
    }
    
    /**
     * Check for login from new IP
     */
    private function is_new_ip($log) {
        if (!$this->db) {
            return false;
        }
        
        try {
            $source_ip = $log['source_ip'] ?? null;
            $user = $log['user'] ?? null;
            
            if (!$source_ip || !$user) {
                return false;
            }
            
            // Check if this user has logged in from this IP before
            $query = "SELECT COUNT(*) as count FROM security_events 
                     WHERE user_account = ? AND source_ip = ? 
                     AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)";
            
            $stmt = $this->db->prepare($query);
            $stmt->bind_param('ss', $user, $source_ip);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            return $row['count'] == 0;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Check for file activity in system directories
     */
    private function is_system_directory_access($text_lower) {
        $system_dirs = [
            'system32', 'windows', 'program files', 'windir',
            'drivers', 'system', 'sysroot', 'boot'
        ];
        
        foreach ($system_dirs as $dir) {
            if (strpos($text_lower, $dir) !== false) {
                // Check if it's a write/delete operation
                if (strpos($text_lower, 'write') !== false || 
                    strpos($text_lower, 'delete') !== false ||
                    strpos($text_lower, 'modified') !== false) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Generate reason for the analysis
     */
    private function generate_reason($text_lower, $category, $severity) {
        $reasons = [];
        
        // Category-specific reasons
        switch ($category) {
            case 'Authentication':
                if (strpos($text_lower, 'failed') !== false) {
                    $reasons[] = 'Failed login attempt detected';
                } else {
                    $reasons[] = 'User authentication event';
                }
                break;
            case 'Process Creation':
                if (strpos($text_lower, 'powershell') !== false) {
                    $reasons[] = 'PowerShell process execution';
                } elseif (strpos($text_lower, 'cmd') !== false) {
                    $reasons[] = 'Command prompt execution';
                } else {
                    $reasons[] = 'Process creation event';
                }
                break;
            case 'Network Connection':
                $reasons[] = 'Network activity detected';
                if (preg_match('/port\s*[>:]\s*(\d+)/', $text_lower, $matches)) {
                    if ($matches[1] > 50000) {
                        $reasons[] = 'Rare port number (' . $matches[1] . ')';
                    }
                }
                break;
            case 'File Access':
                $reasons[] = 'File system activity';
                if (strpos($text_lower, 'system32') !== false) {
                    $reasons[] = 'System directory access';
                }
                break;
            case 'System Error':
                $reasons[] = 'System error or warning';
                if (strpos($text_lower, 'critical') !== false) {
                    $reasons[] = 'Critical severity level';
                }
                break;
            case 'Malware or Suspicious Activity':
                $reasons[] = 'Suspicious activity indicators detected';
                if (strpos($text_lower, 'base64') !== false) {
                    $reasons[] = 'Base64 encoding detected';
                }
                if (strpos($text_lower, 'privilege') !== false) {
                    $reasons[] = 'Privilege escalation attempt';
                }
                break;
        }
        
        // Severity-based reasons
        if ($severity >= 9) {
            $reasons[] = 'Critical severity - immediate escalation required';
        } elseif ($severity >= 7) {
            $reasons[] = 'High severity - requires investigation';
        } elseif ($severity >= 5) {
            $reasons[] = 'Medium severity - monitor and verify';
        }
        
        return implode('; ', $reasons);
    }
    
    /**
     * Generate recommendation
     */
    private function generate_recommendation($category, $severity, $anomaly) {
        $recommendations = [];
        
        // Category-based recommendations
        switch ($category) {
            case 'Authentication':
                $recommendations[] = 'Review authentication logs for failed attempts';
                $recommendations[] = 'Consider password reset if account compromised';
                if ($severity >= 7) {
                    $recommendations[] = 'Block suspicious IP address';
                }
                break;
            case 'Process Creation':
                $recommendations[] = 'Investigate the executable and its source';
                $recommendations[] = 'Check process parent and command line arguments';
                if (strpos($category, 'powershell') !== false) {
                    $recommendations[] = 'Review PowerShell script block logs';
                }
                break;
            case 'Network Connection':
                $recommendations[] = 'Check firewall rules and network policies';
                $recommendations[] = 'Verify destination IP and port legitimacy';
                $recommendations[] = 'Monitor for data exfiltration';
                break;
            case 'File Access':
                $recommendations[] = 'Verify file integrity and permissions';
                $recommendations[] = 'Check file modification history';
                if ($severity >= 6) {
                    $recommendations[] = 'Restore from backup if unauthorized modification';
                }
                break;
            case 'System Error':
                $recommendations[] = 'Check system logs for error details';
                $recommendations[] = 'Verify system resources (CPU, memory, disk)';
                $recommendations[] = 'Consider restarting affected service';
                break;
            case 'Malware or Suspicious Activity':
                $recommendations[] = 'Isolate affected system from network';
                $recommendations[] = 'Run antivirus and malware scans';
                $recommendations[] = 'Preserve evidence for forensic analysis';
                $recommendations[] = 'Escalate to SOC Level 2 immediately';
                break;
        }
        
        // Severity-based recommendations
        if ($severity >= 9) {
            $recommendations[] = 'ESCALATE TO SOC LEVEL 2 IMMEDIATELY';
        } elseif ($severity >= 7) {
            $recommendations[] = 'Escalate to SOC Level 2 for investigation';
        }
        
        // Anomaly-based recommendations
        if ($anomaly) {
            $recommendations[] = 'Anomaly detected - requires investigation';
        }
        
        return implode('; ', array_unique($recommendations));
    }
    
    /**
     * Get all category rules
     */
    public function get_category_rules() {
        return $this->category_rules;
    }
    
    /**
     * Get all severity keywords
     */
    public function get_severity_keywords() {
        return $this->severity_keywords;
    }
}

?>
