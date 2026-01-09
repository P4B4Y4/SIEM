<?php
/**
 * JFS SIEM Threat Detection Engine
 * 
 * Analyzes normalized logs against static detection rules
 * Produces structured security alerts with recommended actions
 */

class ThreatDetectionEngine {
    private $db;
    private $failed_logins = [];
    private $crash_events = [];
    private $shutdown_events = [];
    private $generic_dedup_window_seconds = 600;
    
    // Alert severity levels
    const SEVERITY_LOW = 'low';
    const SEVERITY_MEDIUM = 'medium';
    const SEVERITY_HIGH = 'high';
    const SEVERITY_CRITICAL = 'critical';
    
    // Detection rules database
    private $rules = [];
    
    public function __construct($database = null) {
        $this->db = $database;
        $this->initialize_rules();
    }
    
    /**
     * Initialize all detection rules
     */
    private function initialize_rules() {
        $this->rules = [
            // CRITICAL RULES
            '1102' => [
                'title' => 'Security Logs Cleared',
                'severity' => self::SEVERITY_CRITICAL,
                'category' => 'log_tampering',
                'description' => 'Security event log has been cleared. This is a critical indicator of log tampering.',
                'recommended_actions' => [
                    'Immediately investigate who cleared the logs',
                    'Check for unauthorized access during the gap',
                    'Review backup logs if available',
                    'Enable log protection and immutability settings'
                ]
            ],
            '7045' => [
                'title' => 'New Service Installed',
                'severity' => self::SEVERITY_CRITICAL,
                'category' => 'persistence',
                'description' => 'A new service has been installed on the system. This could indicate malware persistence.',
                'recommended_actions' => [
                    'Verify the service is legitimate',
                    'Check service binary location and signature',
                    'Review service startup type and account',
                    'Scan binary with antivirus',
                    'Check for suspicious registry modifications'
                ]
            ],
            '7031' => [
                'title' => 'Critical Service Crash',
                'severity' => self::SEVERITY_CRITICAL,
                'category' => 'service_crash',
                'description' => 'A critical service has crashed unexpectedly.',
                'recommended_actions' => [
                    'Check service logs for error details',
                    'Verify system resources (CPU, memory, disk)',
                    'Check for recent updates or changes',
                    'Review application event log for related errors',
                    'Restart the service and monitor for recurrence'
                ]
            ],
            '1000' => [
                'title' => 'Application Crash',
                'severity' => self::SEVERITY_CRITICAL,
                'category' => 'application_crash',
                'description' => 'An application has crashed unexpectedly.',
                'recommended_actions' => [
                    'Review application error details',
                    'Check for memory corruption or buffer overflow',
                    'Verify application is up to date',
                    'Check for hardware issues',
                    'Review recent changes to the system'
                ]
            ],
            '4697' => [
                'title' => 'New Service Added (Possible Persistence)',
                'severity' => self::SEVERITY_CRITICAL,
                'category' => 'persistence',
                'description' => 'A new service has been added to the system. This is a common malware persistence technique.',
                'recommended_actions' => [
                    'Verify service legitimacy immediately',
                    'Check service binary path and digital signature',
                    'Review service account and permissions',
                    'Scan binary with updated antivirus',
                    'Check for suspicious registry entries',
                    'Review process creation logs for service installation'
                ]
            ],
            'bruteforce' => [
                'title' => 'Brute-Force Login Attempt Detected',
                'severity' => self::SEVERITY_CRITICAL,
                'category' => 'brute_force',
                'description' => '10 or more failed login attempts detected within 5 minutes.',
                'recommended_actions' => [
                    'Immediately check for successful intrusions',
                    'Review successful logins during and after attack',
                    'Enable account lockout policies',
                    'Implement IP-based blocking',
                    'Review and strengthen password policies',
                    'Enable MFA on critical accounts'
                ]
            ],

            'disk_anomaly' => [
                'title' => 'Disk Anomaly Detected',
                'severity' => self::SEVERITY_CRITICAL,
                'category' => 'system_health',
                'description' => 'A disk anomaly was reported by an agent. This may indicate disk failure, ransomware activity, or abnormal IO behavior.',
                'recommended_actions' => [
                    'Review disk usage and IO patterns',
                    'Check for unexpected file modifications/encryption activity',
                    'Run antivirus scan and ransomware checks',
                    'Check SMART status and system logs for disk errors',
                    'Verify backups are current'
                ]
            ],

            'memory_anomaly' => [
                'title' => 'Memory Anomaly Detected',
                'severity' => self::SEVERITY_HIGH,
                'category' => 'system_health',
                'description' => 'A memory anomaly was reported by an agent. This may indicate memory exhaustion, leak, or suspicious behavior.',
                'recommended_actions' => [
                    'Review memory usage and top processes',
                    'Check for suspicious processes and injections',
                    'Review recent software/patch changes',
                    'Collect a memory dump if incident suspected',
                    'Monitor for recurrence'
                ]
            ],
            
            // HIGH SEVERITY RULES
            '4688_cmd' => [
                'title' => 'Suspicious Command Prompt Execution',
                'severity' => self::SEVERITY_HIGH,
                'category' => 'command_execution',
                'description' => 'cmd.exe has been executed. This is often used for malicious activities.',
                'recommended_actions' => [
                    'Review the parent process that launched cmd.exe',
                    'Check command line arguments',
                    'Verify the user account that executed it',
                    'Check for suspicious child processes',
                    'Review network connections made by cmd.exe'
                ]
            ],
            '4688_powershell' => [
                'title' => 'Suspicious PowerShell Execution',
                'severity' => self::SEVERITY_HIGH,
                'category' => 'command_execution',
                'description' => 'PowerShell has been executed. This is commonly used for advanced attacks.',
                'recommended_actions' => [
                    'Review PowerShell command line arguments',
                    'Check parent process that launched PowerShell',
                    'Verify user account and privileges',
                    'Check for script block logging entries',
                    'Review network connections and file modifications'
                ]
            ],
            '4104' => [
                'title' => 'PowerShell Script Block Logged',
                'severity' => self::SEVERITY_HIGH,
                'category' => 'script_execution',
                'description' => 'PowerShell script block has been logged. Review for malicious content.',
                'recommended_actions' => [
                    'Analyze the PowerShell script content',
                    'Check for obfuscation or encoding',
                    'Verify script source and legitimacy',
                    'Review execution context and user',
                    'Check for network or file system modifications'
                ]
            ],
            '6008' => [
                'title' => 'Unexpected System Shutdown',
                'severity' => self::SEVERITY_HIGH,
                'category' => 'system_shutdown',
                'description' => 'System has shut down unexpectedly.',
                'recommended_actions' => [
                    'Check system event log for shutdown reason',
                    'Review for power loss or hardware issues',
                    'Check for malware forcing shutdown',
                    'Verify recent system changes',
                    'Review security logs for suspicious activity before shutdown'
                ]
            ],
            
            // MEDIUM SEVERITY RULES
            '4720' => [
                'title' => 'New User Account Created',
                'severity' => self::SEVERITY_MEDIUM,
                'category' => 'account_management',
                'description' => 'A new user account has been created.',
                'recommended_actions' => [
                    'Verify the account creation is authorized',
                    'Check account properties and group memberships',
                    'Review who created the account',
                    'Monitor the new account for suspicious activity',
                    'Verify account is needed for business purposes'
                ]
            ],
            '4728' => [
                'title' => 'User Added to Group',
                'severity' => self::SEVERITY_MEDIUM,
                'category' => 'privilege_change',
                'description' => 'A user has been added to a group.',
                'recommended_actions' => [
                    'Verify the group membership change is authorized',
                    'Check which group the user was added to',
                    'Review who made the change',
                    'Verify the user should have these permissions',
                    'Monitor for privilege escalation attempts'
                ]
            ],
            '4732' => [
                'title' => 'User Added to Admin Group',
                'severity' => self::SEVERITY_MEDIUM,
                'category' => 'privilege_escalation',
                'description' => 'A user has been added to an administrative group.',
                'recommended_actions' => [
                    'Verify the privilege escalation is authorized',
                    'Check if the user should have admin rights',
                    'Review who granted the privileges',
                    'Monitor the account for suspicious activity',
                    'Implement principle of least privilege'
                ]
            ],
            'repeated_crashes' => [
                'title' => 'Repeated Application Crashes Detected',
                'severity' => self::SEVERITY_MEDIUM,
                'category' => 'application_stability',
                'description' => '3 or more application crashes detected in a short time period.',
                'recommended_actions' => [
                    'Identify the crashing application',
                    'Check for memory leaks or resource issues',
                    'Verify application is properly installed',
                    'Check for hardware issues',
                    'Review recent system changes or updates'
                ]
            ],
            
            // LOW SEVERITY RULES
            '4624' => [
                'title' => 'User Login',
                'severity' => self::SEVERITY_LOW,
                'category' => 'authentication',
                'description' => 'A user has successfully logged in.',
                'recommended_actions' => [
                    'Monitor for unusual login patterns',
                    'Verify login location and time are expected',
                    'Check for concurrent sessions'
                ]
            ],
            '7036' => [
                'title' => 'Service Status Changed',
                'severity' => self::SEVERITY_LOW,
                'category' => 'service_management',
                'description' => 'A service status has changed.',
                'recommended_actions' => [
                    'Verify the service status change is expected',
                    'Check service logs for details'
                ]
            ],
            '6005' => [
                'title' => 'System Startup',
                'severity' => self::SEVERITY_LOW,
                'category' => 'system_event',
                'description' => 'The system has started up.',
                'recommended_actions' => [
                    'Verify startup was expected',
                    'Check for unexpected services starting'
                ]
            ],
            '6006' => [
                'title' => 'System Shutdown',
                'severity' => self::SEVERITY_LOW,
                'category' => 'system_event',
                'description' => 'The system has shut down normally.',
                'recommended_actions' => [
                    'Verify shutdown was expected'
                ]
            ]
        ];
    }
    
    /**
     * Main function: Evaluate a log against all detection rules
     * 
     * @param array $log Normalized log entry
     * @return array|null Alert if matched, null if no match
     */
    public function evaluate_log($log) {
        // Validate input
        if (!is_array($log) || empty($log['event_id'])) {
            return null;
        }
        
        $event_id = (string)$log['event_id'];
        
        // Check for direct event ID matches
        if (isset($this->rules[$event_id])) {
            return $this->create_alert($log, $event_id, $this->rules[$event_id]);
        }
        
        // Check for process-based rules (cmd.exe, powershell.exe)
        if ($event_id === '4688') {
            return $this->check_process_execution($log);
        }
        
        // Check for brute-force attempts
        if ($event_id === '4625') {
            $bruteforce_alert = $this->check_bruteforce($log);
            if ($bruteforce_alert) {
                return $bruteforce_alert;
            }
        }
        
        // Check for repeated crashes
        if ($event_id === '1000') {
            $crash_alert = $this->check_repeated_crashes($log);
            if ($crash_alert) {
                return $crash_alert;
            }
        }
        
        // Check for repeated shutdowns
        if ($event_id === '6008') {
            $shutdown_alert = $this->check_repeated_shutdowns($log);
            if ($shutdown_alert) {
                return $shutdown_alert;
            }
        }
        
        // Check for crash correlation (7031 + 1000)
        if ($event_id === '7031') {
            $correlation_alert = $this->check_crash_correlation($log);
            if ($correlation_alert) {
                return $correlation_alert;
            }
        }

        // Fallback: generate alerts for high/critical events even if no explicit rule exists
        $sev = isset($log['severity']) ? strtolower((string)$log['severity']) : '';
        if ($sev === self::SEVERITY_HIGH || $sev === self::SEVERITY_CRITICAL || $sev === 'high' || $sev === 'critical') {
            return $this->create_generic_severity_alert($log, $event_id, $sev);
        }

        return null;
    }

    private function create_generic_severity_alert($log, $event_id, $sev) {
        $rule_id = 'generic_' . $sev;
        $title_sev = ($sev === self::SEVERITY_CRITICAL || $sev === 'critical') ? 'Critical' : 'High';

        if ($this->should_suppress_generic_alert($log, $event_id, $rule_id)) {
            return null;
        }

        $rule_definition = [
            'title' => $title_sev . ' Severity Event: ' . $event_id,
            'severity' => ($sev === 'critical') ? self::SEVERITY_CRITICAL : self::SEVERITY_HIGH,
            'category' => 'agent_event',
            'description' => 'High/critical event received from agent without a dedicated detection rule.',
            'recommended_actions' => [
                'Review the event details and raw log',
                'Validate whether this event type should have a dedicated rule',
                'Check the affected endpoint for abnormal behavior',
                'Investigate related events around the same timestamp'
            ]
        ];

        $alert = $this->create_alert($log, $rule_id, $rule_definition);
        $alert['details']['event_type'] = $event_id;
        return $alert;
    }

    private function should_suppress_generic_alert($log, $event_id, $rule_id) {
        if (!$this->db) {
            return false;
        }

        $computer = isset($log['computer']) ? (string)$log['computer'] : 'unknown';
        $event_type = (string)$event_id;
        $threshold = date('Y-m-d H:i:s', time() - $this->generic_dedup_window_seconds);

        $stmt = $this->db->prepare(
            "SELECT 1 FROM security_alerts WHERE rule_id = ? AND matched_event_id = ? AND timestamp >= ? AND details LIKE ? LIMIT 1"
        );
        if (!$stmt) {
            return false;
        }

        $details_like = '%"computer":"' . $this->db->real_escape_string($computer) . '"%';
        $stmt->bind_param('ssss', $rule_id, $event_type, $threshold, $details_like);
        $stmt->execute();
        $res = $stmt->get_result();
        $exists = ($res && $res->num_rows > 0);
        $stmt->close();

        return $exists;
    }
    
    /**
     * Check for process execution rules
     */
    private function check_process_execution($log) {
        $process_name = isset($log['process_name']) ? strtolower($log['process_name']) : '';
        
        if (strpos($process_name, 'cmd.exe') !== false) {
            return $this->create_alert($log, '4688_cmd', $this->rules['4688_cmd']);
        }
        
        if (strpos($process_name, 'powershell.exe') !== false) {
            return $this->create_alert($log, '4688_powershell', $this->rules['4688_powershell']);
        }
        
        return null;
    }
    
    /**
     * Check for brute-force login attempts
     * Detects 10+ failed logins within 5 minutes
     */
    public function check_bruteforce($log) {
        $timestamp = strtotime($log['timestamp']);
        $source_ip = isset($log['source_ip']) ? $log['source_ip'] : 'unknown';
        $user = isset($log['user']) ? $log['user'] : 'unknown';
        
        // Create unique key for source IP + user combination
        $key = $source_ip . '_' . $user;
        
        // Initialize tracking array if needed
        if (!isset($this->failed_logins[$key])) {
            $this->failed_logins[$key] = [];
        }
        
        // Add current failed login
        $this->failed_logins[$key][] = $timestamp;
        
        // Remove old entries (older than 5 minutes)
        $five_minutes_ago = $timestamp - 300;
        $this->failed_logins[$key] = array_filter(
            $this->failed_logins[$key],
            function($ts) use ($five_minutes_ago) {
                return $ts >= $five_minutes_ago;
            }
        );
        
        // Check if we have 10+ failures in 5 minutes
        if (count($this->failed_logins[$key]) >= 10) {
            $alert = $this->create_alert($log, 'bruteforce', $this->rules['bruteforce']);
            $alert['details']['failed_attempts'] = count($this->failed_logins[$key]);
            $alert['details']['source_ip'] = $source_ip;
            $alert['details']['target_user'] = $user;
            $alert['details']['time_window'] = '5 minutes';
            
            // Clear the tracking for this key
            unset($this->failed_logins[$key]);
            
            return $alert;
        }
        
        return null;
    }
    
    /**
     * Check for repeated application crashes
     * Detects 3+ crashes within a time window
     */
    private function check_repeated_crashes($log) {
        $timestamp = strtotime($log['timestamp']);
        $computer = isset($log['computer']) ? $log['computer'] : 'unknown';
        
        // Initialize tracking array if needed
        if (!isset($this->crash_events[$computer])) {
            $this->crash_events[$computer] = [];
        }
        
        // Add current crash
        $this->crash_events[$computer][] = $timestamp;
        
        // Remove old entries (older than 30 minutes)
        $thirty_minutes_ago = $timestamp - 1800;
        $this->crash_events[$computer] = array_filter(
            $this->crash_events[$computer],
            function($ts) use ($thirty_minutes_ago) {
                return $ts >= $thirty_minutes_ago;
            }
        );
        
        // Check if we have 3+ crashes in 30 minutes
        if (count($this->crash_events[$computer]) >= 3) {
            $alert = $this->create_alert($log, 'repeated_crashes', $this->rules['repeated_crashes']);
            $alert['details']['crash_count'] = count($this->crash_events[$computer]);
            $alert['details']['computer'] = $computer;
            $alert['details']['time_window'] = '30 minutes';
            
            return $alert;
        }
        
        return null;
    }
    
    /**
     * Check for repeated unexpected shutdowns
     */
    private function check_repeated_shutdowns($log) {
        $timestamp = strtotime($log['timestamp']);
        $computer = isset($log['computer']) ? $log['computer'] : 'unknown';
        
        // Initialize tracking array if needed
        if (!isset($this->shutdown_events[$computer])) {
            $this->shutdown_events[$computer] = [];
        }
        
        // Add current shutdown
        $this->shutdown_events[$computer][] = $timestamp;
        
        // Remove old entries (older than 1 hour)
        $one_hour_ago = $timestamp - 3600;
        $this->shutdown_events[$computer] = array_filter(
            $this->shutdown_events[$computer],
            function($ts) use ($one_hour_ago) {
                return $ts >= $one_hour_ago;
            }
        );
        
        // Check if we have 3+ shutdowns in 1 hour
        if (count($this->shutdown_events[$computer]) >= 3) {
            $alert = $this->create_alert($log, '6008', $this->rules['6008']);
            $alert['details']['shutdown_count'] = count($this->shutdown_events[$computer]);
            $alert['details']['computer'] = $computer;
            $alert['details']['time_window'] = '1 hour';
            
            return $alert;
        }
        
        return null;
    }
    
    /**
     * Check for crash correlation (7031 + 1000)
     * Service crash followed by application crash
     */
    private function check_crash_correlation($log) {
        // This would require database queries to check recent 1000 events
        // For now, we'll flag the 7031 event and let correlation happen in database
        $alert = $this->create_alert($log, '7031', $this->rules['7031']);
        $alert['details']['correlation_type'] = 'service_crash';
        $alert['details']['note'] = 'Check for related application crashes (Event ID 1000) within 5 minutes';
        
        return $alert;
    }
    
    /**
     * Create a structured alert from a matched rule
     */
    private function create_alert($log, $rule_id, $rule_definition) {
        $alert_id = 'ALERT_' . strtoupper(substr(md5(microtime(true) . rand()), 0, 8));
        
        return [
            'alert_id' => $alert_id,
            'title' => $rule_definition['title'],
            'severity' => $rule_definition['severity'],
            'rule_id' => $rule_id,
            'matched_event_id' => isset($log['event_id']) ? $log['event_id'] : 'unknown',
            'timestamp' => $log['timestamp'] ?? date('Y-m-d H:i:s'),
            'category' => $rule_definition['category'] ?? 'uncategorized',
            'description' => $rule_definition['description'],
            'details' => [
                'computer' => $log['computer'] ?? 'unknown',
                'user' => $log['user'] ?? 'unknown',
                'source' => $log['source'] ?? 'unknown',
                'log_type' => $log['log_type'] ?? 'unknown'
            ],
            'recommended_actions' => $rule_definition['recommended_actions'] ?? [],
            'raw_log' => $log
        ];
    }
    
    /**
     * Get all available rules
     */
    public function get_rules() {
        return $this->rules;
    }
    
    /**
     * Get rule by ID
     */
    public function get_rule($rule_id) {
        return isset($this->rules[$rule_id]) ? $this->rules[$rule_id] : null;
    }
    
    /**
     * Get rules by severity
     */
    public function get_rules_by_severity($severity) {
        $filtered = [];
        foreach ($this->rules as $id => $rule) {
            if (isset($rule['severity']) && $rule['severity'] === $severity) {
                $filtered[$id] = $rule;
            }
        }
        return $filtered;
    }
    
    /**
     * Get rules by category
     */
    public function get_rules_by_category($category) {
        $filtered = [];
        foreach ($this->rules as $id => $rule) {
            if (isset($rule['category']) && $rule['category'] === $category) {
                $filtered[$id] = $rule;
            }
        }
        return $filtered;
    }
    
    /**
     * Store alert in database
     */
    public function store_alert($alert) {
        if (!$this->db) {
            return false;
        }
        
        try {
            $query = "INSERT INTO security_alerts (
                alert_id, title, severity, rule_id, matched_event_id, 
                timestamp, category, description, details, recommended_actions, raw_log, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";
            
            $stmt = $this->db->prepare($query);
            if (!$stmt) {
                return false;
            }
            
            $details_json = json_encode($alert['details']);
            $actions_json = json_encode($alert['recommended_actions']);
            $raw_log_json = json_encode($alert['raw_log']);
            
            $stmt->bind_param(
                'sssssssssss',
                $alert['alert_id'],
                $alert['title'],
                $alert['severity'],
                $alert['rule_id'],
                $alert['matched_event_id'],
                $alert['timestamp'],
                $alert['category'],
                $alert['description'],
                $details_json,
                $actions_json,
                $raw_log_json
            );

            $ok = $stmt->execute();
            $stmt->close();

            if ($ok) {
                $this->send_alert_email_notification($alert);
            }

            return $ok;
        } catch (Exception $e) {
            error_log('Error storing alert: ' . $e->getMessage());
            return false;
        }
    }

    private function send_alert_email_notification($alert) {
        try {
            require_once __DIR__ . '/settings.php';
            require_once __DIR__ . '/alert_notifier.php';

            $smtp_settings = (array)getSetting('smtp', []);
            $email_notifications_enabled = (bool)getSetting('email_notifications.enabled', false);
            $default_recipients = (string)getSetting('email_notifications.default_recipients', '');

            if (!$email_notifications_enabled || $default_recipients === '') {
                return;
            }

            $smtp_config = [
                'host' => $smtp_settings['host'] ?? (getenv('SMTP_HOST') ?: 'localhost'),
                'port' => (int)($smtp_settings['port'] ?? (getenv('SMTP_PORT') ?: 587)),
                'user' => $smtp_settings['username'] ?? (getenv('SMTP_USER') ?: ''),
                'pass' => $smtp_settings['password'] ?? (getenv('SMTP_PASS') ?: ''),
                'from_email' => $smtp_settings['from_email'] ?? (getenv('SMTP_FROM') ?: 'siem@localhost'),
                'from_name' => $smtp_settings['from_name'] ?? 'SIEM Alert System',
                'use_smtp' => (bool)($smtp_settings['enabled'] ?? (bool)(getenv('USE_SMTP') ?: false)),
                'encryption' => $smtp_settings['encryption'] ?? null
            ];

            $notifier = new AlertNotifier($smtp_config);
            $sent = $notifier->send_alert_email($this->map_alert_for_notifier($alert), $default_recipients);
            if (!$sent) {
                error_log('Alert email send failed for alert_id=' . ($alert['alert_id'] ?? 'unknown') . ' error=' . ($notifier->get_last_error() ?? 'unknown'));
            }
        } catch (Exception $e) {
            error_log('Alert email exception: ' . $e->getMessage());
        }
    }

    private function map_alert_for_notifier($alert) {
        $out = is_array($alert) ? $alert : [];
        if (!isset($out['alert_level'])) {
            $sev = isset($out['severity']) ? strtolower((string)$out['severity']) : '';
            if ($sev === self::SEVERITY_CRITICAL || $sev === 'critical' || $sev === 'high') {
                $out['alert_level'] = 'Critical';
            } elseif ($sev === self::SEVERITY_MEDIUM || $sev === 'medium') {
                $out['alert_level'] = 'Warning';
            } else {
                $out['alert_level'] = 'Informational';
            }
        }

        if (!isset($out['computer'])) {
            $out['computer'] = $out['details']['computer'] ?? 'N/A';
        }
        if (!isset($out['source'])) {
            $out['source'] = $out['details']['source'] ?? 'SIEM';
        }
        if (!isset($out['anomaly'])) {
            $out['anomaly'] = 'Yes';
        }
        if (!isset($out['reason'])) {
            $out['reason'] = $out['description'] ?? '';
        }
        if (!isset($out['recommendation'])) {
            $actions = $out['recommended_actions'] ?? [];
            if (is_array($actions) && !empty($actions)) {
                $out['recommendation'] = implode("\n", array_map('strval', $actions));
            } else {
                $out['recommendation'] = '';
            }
        }
        if (!isset($out['escalation'])) {
            $out['escalation'] = 'Review in normal shift';
        }

        return $out;
    }
    
    /**
     * Get alert statistics
     */
    public function get_alert_stats() {
        if (!$this->db) {
            return null;
        }
        
        $stats = [
            'total' => 0,
            'by_severity' => [
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0
            ],
            'by_category' => []
        ];
        
        try {
            // Total alerts
            $result = $this->db->query("SELECT COUNT(*) as count FROM security_alerts");
            if ($result) {
                $row = $result->fetch_assoc();
                $stats['total'] = $row['count'];
            }
            
            // By severity
            $result = $this->db->query("SELECT severity, COUNT(*) as count FROM security_alerts GROUP BY severity");
            if ($result) {
                while ($row = $result->fetch_assoc()) {
                    if (isset($stats['by_severity'][$row['severity']])) {
                        $stats['by_severity'][$row['severity']] = $row['count'];
                    }
                }
            }
            
            // By category
            $result = $this->db->query("SELECT category, COUNT(*) as count FROM security_alerts GROUP BY category");
            if ($result) {
                while ($row = $result->fetch_assoc()) {
                    $stats['by_category'][$row['category']] = $row['count'];
                }
            }
        } catch (Exception $e) {
            error_log('Error getting alert stats: ' . $e->getMessage());
        }
        
        return $stats;
    }
}

?>
