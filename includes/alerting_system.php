<?php
/**
 * SIEM Alerting System (Part 4)
 * 
 * Standalone module that converts detection outputs into structured alerts
 * with severity mapping, escalation rules, and unique alert IDs.
 * 
 * Can run independently without SIEM backend connection.
 */

class AlertingSystem {
    
    /**
     * Severity to Alert Level Mapping
     */
    private $severity_mapping = [
        'low' => 'Informational',
        'medium' => 'Warning',
        'high' => 'Critical',
        'critical' => 'Critical'
    ];
    
    /**
     * Numeric severity thresholds for escalation
     */
    private $escalation_thresholds = [
        8 => 'Escalate to SOC Level 2 immediately',
        5 => 'Investigate within 1 hour',
        0 => 'Review in normal shift'
    ];
    
    /**
     * Category to brief description mapping
     */
    private $category_descriptions = [
        'Authentication' => 'Unauthorized Access Attempt',
        'Process Creation' => 'Suspicious Process Execution',
        'Network Connection' => 'Unusual Network Activity',
        'File Access' => 'Unauthorized File Access',
        'System Error' => 'System Failure Detected',
        'Malware or Suspicious Activity' => 'Potential Malware Detected'
    ];
    
    /**
     * Generate a unique alert ID
     * Format: ALERT_XXXXXXXX (8 random hex characters)
     */
    public function generate_alert_id() {
        return 'ALERT_' . strtoupper(bin2hex(random_bytes(4)));
    }
    
    /**
     * Map severity string to alert level
     * 
     * @param string $severity Severity level (low, medium, high, critical)
     * @return string Alert level (Informational, Warning, Critical)
     */
    public function map_severity_to_alert_level($severity) {
        $severity_lower = strtolower($severity);
        return $this->severity_mapping[$severity_lower] ?? 'Informational';
    }
    
    /**
     * Convert numeric severity to escalation instruction
     * 
     * @param string|int $severity Severity level or numeric score
     * @return string Escalation instruction
     */
    public function get_escalation_instruction($severity) {
        // If severity is a string, convert to numeric
        if (is_string($severity)) {
            $severity_map = ['low' => 3, 'medium' => 5, 'high' => 7, 'critical' => 10];
            $numeric_severity = $severity_map[strtolower($severity)] ?? 3;
        } else {
            $numeric_severity = (int)$severity;
        }
        
        // Determine escalation based on threshold
        if ($numeric_severity >= 8) {
            return 'Escalate to SOC Level 2 immediately';
        } elseif ($numeric_severity >= 5) {
            return 'Investigate within 1 hour';
        } else {
            return 'Review in normal shift';
        }
    }
    
    /**
     * Generate a title for the alert
     * Format: "<Category> - <Brief Description>"
     * 
     * @param string $category Detection category
     * @param string $reason Detection reason (optional)
     * @return string Alert title
     */
    public function generate_alert_title($category, $reason = '') {
        $description = $this->category_descriptions[$category] ?? 'Security Event Detected';
        
        // If reason is provided and is meaningful, use it
        if (!empty($reason) && strlen($reason) < 50) {
            return "$category - $reason";
        }
        
        return "$category - $description";
    }
    
    /**
     * Process a single detection and convert to alert
     * 
     * @param array $detection Detection output with required fields
     * @return array|false Alert array or false if invalid
     */
    public function process_detection($detection) {
        // Validate required fields
        $required_fields = ['event_id', 'timestamp', 'computer', 'source', 'category', 'severity'];
        
        foreach ($required_fields as $field) {
            if (!isset($detection[$field])) {
                error_log("Missing required field: $field");
                return false;
            }
        }
        
        // Generate alert
        $alert = [
            'alert_id' => $this->generate_alert_id(),
            'title' => $this->generate_alert_title(
                $detection['category'],
                $detection['reason'] ?? ''
            ),
            'alert_level' => $this->map_severity_to_alert_level($detection['severity']),
            'timestamp' => $detection['timestamp'],
            'computer' => $detection['computer'],
            'source' => $detection['source'],
            'category' => $detection['category'],
            'severity' => $detection['severity'],
            'anomaly' => $detection['anomaly'] ?? 'No',
            'reason' => $detection['reason'] ?? '',
            'recommendation' => $detection['recommendation'] ?? '',
            'escalation' => $this->get_escalation_instruction($detection['severity']),
            'raw_log' => $detection['raw_log'] ?? []
        ];
        
        return $alert;
    }
    
    /**
     * Process a batch of detections and convert to alerts
     * 
     * @param array $detections Array of detection outputs
     * @return array Array of alerts with status
     */
    public function process_batch($detections) {
        if (!is_array($detections)) {
            return [
                'success' => false,
                'error' => 'Input must be an array of detections',
                'alerts' => [],
                'total' => 0,
                'processed' => 0,
                'failed' => 0
            ];
        }
        
        $alerts = [];
        $processed = 0;
        $failed = 0;
        
        foreach ($detections as $index => $detection) {
            $alert = $this->process_detection($detection);
            
            if ($alert) {
                $alerts[] = $alert;
                $processed++;
            } else {
                $failed++;
                error_log("Failed to process detection at index $index");
            }
        }
        
        return [
            'success' => true,
            'alerts' => $alerts,
            'total' => count($detections),
            'processed' => $processed,
            'failed' => $failed
        ];
    }
    
    /**
     * Get severity mapping (for reference)
     */
    public function get_severity_mapping() {
        return $this->severity_mapping;
    }
    
    /**
     * Get escalation thresholds (for reference)
     */
    public function get_escalation_thresholds() {
        return $this->escalation_thresholds;
    }
}

?>
