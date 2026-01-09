<?php
/**
 * Alert Notifier - Email Notification System
 * 
 * Sends email notifications for alerts based on severity and escalation rules
 * Supports SMTP configuration and HTML email templates
 */

class AlertNotifier {
    
    private $smtp_host;
    private $smtp_port;
    private $smtp_user;
    private $smtp_pass;
    private $from_email;
    private $from_name;
    private $use_smtp;
    private $smtp_encryption;
    private $last_error;
    
    /**
     * Initialize notifier with SMTP configuration
     * 
     * @param array $config SMTP configuration
     *   - host: SMTP server hostname
     *   - port: SMTP port (default: 587)
     *   - user: SMTP username
     *   - pass: SMTP password
     *   - from_email: From email address
     *   - from_name: From display name
     *   - use_smtp: Use SMTP (true) or PHP mail() (false)
     */
    public function __construct($config = []) {
        $this->smtp_host = $config['host'] ?? 'localhost';
        $this->smtp_port = $config['port'] ?? 587;
        $this->smtp_user = $config['user'] ?? '';
        $this->smtp_pass = $config['pass'] ?? '';
        $this->from_email = $config['from_email'] ?? 'siem@localhost';
        $this->from_name = $config['from_name'] ?? 'SIEM Alert System';
        $this->use_smtp = $config['use_smtp'] ?? false;
        $this->smtp_encryption = $config['encryption'] ?? null;
        $this->last_error = null;
    }

    public function get_last_error() {
        return $this->last_error;
    }
    
    /**
     * Send alert notification email
     * 
     * @param array $alert Alert data
     * @param string|array $recipient Email address or array of addresses
     * @return bool Success status
     */
    public function send_alert_email($alert, $recipient) {
        if (!is_array($recipient)) {
            $recipient = [$recipient];
        }
        
        // Generate email subject
        $subject = $this->generate_subject($alert);

        // Generate email body (template-based)
        $body = $this->generate_html_body($alert);
        
        // Send email
        return $this->send_email($recipient, $subject, $body);
    }
    
    /**
     * Send batch alert notifications
     * 
     * @param array $alerts Array of alerts
     * @param string|array $recipient Email address or array of addresses
     * @return array Results for each alert
     */
    public function send_batch_alerts($alerts, $recipient) {
        $results = [];
        
        foreach ($alerts as $alert) {
            $results[$alert['alert_id']] = $this->send_alert_email($alert, $recipient);
        }
        
        return $results;
    }
    
    /**
     * Generate email subject based on alert
     */
    private function generate_subject($alert) {
        $severity = strtoupper((string)($alert['severity'] ?? $alert['alert_level'] ?? ''));
        $severity_prefix = $severity !== '' ? '[' . $severity . '] ' : '';

        $computer = (string)($alert['computer'] ?? $alert['source_host'] ?? '');
        $suffix = $computer !== '' ? (' - ' . $computer) : '';

        return $severity_prefix . (string)($alert['title'] ?? 'Security Alert') . $suffix;
    }
    
    /**
     * Generate HTML email body
     */
    private function generate_html_body($alert) {
        $severity = strtoupper((string)($alert['severity'] ?? $alert['alert_level'] ?? ''));
        $severity_class = $this->get_severity_class($severity);

        $severity_label_bg = '#1d4ed8';
        if ($severity_class === 'critical') {
            $severity_label_bg = '#b91c1c';
        } elseif ($severity_class === 'warning') {
            $severity_label_bg = '#b45309';
        }

        $title = htmlspecialchars((string)($alert['title'] ?? 'Security Alert'), ENT_QUOTES, 'UTF-8');
        $alert_id = htmlspecialchars((string)($alert['alert_id'] ?? ''), ENT_QUOTES, 'UTF-8');
        $timestamp = htmlspecialchars((string)($alert['timestamp'] ?? ''), ENT_QUOTES, 'UTF-8');
        $category = htmlspecialchars((string)($alert['category'] ?? ''), ENT_QUOTES, 'UTF-8');
        $status = htmlspecialchars((string)($alert['status'] ?? ''), ENT_QUOTES, 'UTF-8');
        $rule_id = htmlspecialchars((string)($alert['rule_id'] ?? ''), ENT_QUOTES, 'UTF-8');

        $details = '';
        if (isset($alert['description']) && $alert['description'] !== null && $alert['description'] !== '') {
            $details = nl2br(htmlspecialchars((string)$alert['description'], ENT_QUOTES, 'UTF-8'));
        } elseif (isset($alert['details']) && is_array($alert['details'])) {
            $details = nl2br(htmlspecialchars(json_encode($alert['details'], JSON_PRETTY_PRINT), ENT_QUOTES, 'UTF-8'));
        }

        $actions = '';
        if (isset($alert['recommended_actions']) && is_array($alert['recommended_actions']) && !empty($alert['recommended_actions'])) {
            $items = '';
            foreach ($alert['recommended_actions'] as $a) {
                $items .= '<li style="margin:0 0 6px 0">' . htmlspecialchars((string)$a, ENT_QUOTES, 'UTF-8') . '</li>';
            }
            $actions = '<ul style="margin:0;padding-left:18px">' . $items . '</ul>';
        }

        // Table-based layout for better compatibility across email clients
        $details_html = ($details !== '' ? $details : 'No additional details provided.');
        $actions_html = ($actions !== '' ? $actions : 'No recommended actions provided.');

        return "<!DOCTYPE html>
<html>
<head>
  <meta charset=\"UTF-8\">
</head>
<body style=\"margin:0;padding:0;background:#f3f4f6;\">
  <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"background:#f3f4f6;\">
    <tr>
      <td align=\"center\" style=\"padding:20px 12px;\">
        <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"680\" style=\"width:680px;max-width:680px;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;\">
          <tr>
            <td style=\"background:#0f172a;padding:16px 18px;\">
              <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">
                <tr>
                  <td align=\"left\" style=\"font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#e5e7eb;\">JFS SIEM ALERT</td>
                  <td align=\"right\">
                    <span style=\"font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;letter-spacing:.3px;color:#fff;background:{$severity_label_bg};padding:6px 10px;border-radius:999px;display:inline-block;\">{$severity}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td style=\"padding:18px;\">
              <div style=\"font-family:Arial,Helvetica,sans-serif;font-size:18px;font-weight:800;color:#111827;margin:0 0 10px 0;\">{$title}</div>

              <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#111827;border-collapse:collapse;\">
                <tr>
                  <td style=\"padding:8px 0;color:#64748b;font-weight:700;width:160px;border-bottom:1px solid #f1f5f9;\">Alert ID</td>
                  <td style=\"padding:8px 0;border-bottom:1px solid #f1f5f9;\"><code style=\"font-family:Consolas,Menlo,monospace;\">{$alert_id}</code></td>
                </tr>
                <tr>
                  <td style=\"padding:8px 0;color:#64748b;font-weight:700;border-bottom:1px solid #f1f5f9;\">Timestamp</td>
                  <td style=\"padding:8px 0;border-bottom:1px solid #f1f5f9;\">{$timestamp}</td>
                </tr>
                <tr>
                  <td style=\"padding:8px 0;color:#64748b;font-weight:700;border-bottom:1px solid #f1f5f9;\">Category</td>
                  <td style=\"padding:8px 0;border-bottom:1px solid #f1f5f9;\">{$category}</td>
                </tr>
                <tr>
                  <td style=\"padding:8px 0;color:#64748b;font-weight:700;border-bottom:1px solid #f1f5f9;\">Status</td>
                  <td style=\"padding:8px 0;border-bottom:1px solid #f1f5f9;\">{$status}</td>
                </tr>
                <tr>
                  <td style=\"padding:8px 0;color:#64748b;font-weight:700;border-bottom:1px solid #f1f5f9;\">Rule</td>
                  <td style=\"padding:8px 0;border-bottom:1px solid #f1f5f9;\">{$rule_id}</td>
                </tr>
              </table>

              <div style=\"margin-top:16px;font-family:Arial,Helvetica,sans-serif;\">
                <div style=\"font-size:14px;font-weight:800;color:#111827;margin:0 0 8px 0;\">Details</div>
                <div style=\"background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:12px;color:#0f172a;font-size:13px;line-height:1.5;\">{$details_html}</div>
              </div>

              <div style=\"margin-top:16px;font-family:Arial,Helvetica,sans-serif;\">
                <div style=\"font-size:14px;font-weight:800;color:#111827;margin:0 0 8px 0;\">Immediate Actions</div>
                <div style=\"background:#ecfeff;border:1px solid #a5f3fc;border-radius:10px;padding:12px;color:#0f172a;font-size:13px;line-height:1.5;\">{$actions_html}</div>
              </div>
            </td>
          </tr>

          <tr>
            <td style=\"padding:12px 18px;background:#f9fafb;border-top:1px solid #e5e7eb;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#64748b;\">
              Automated SIEM alert. Please review and acknowledge/resolve in the SIEM dashboard.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>";
    }
    
    /**
     * Get CSS severity class
     */
    private function get_severity_class($alert_level) {
        switch (strtoupper($alert_level)) {
            case 'CRITICAL':
                return 'critical';
            case 'WARNING':
                return 'warning';
            case 'INFORMATIONAL':
                return 'informational';
            default:
                return 'informational';
        }
    }
    
    /**
     * Send email using SMTP or PHP mail()
     */
    private function send_email($recipients, $subject, $body) {
        $this->last_error = null;
        if ($this->use_smtp) {
            return $this->send_via_smtp($recipients, $subject, $body);
        } else {
            return $this->send_via_mail($recipients, $subject, $body);
        }
    }
    
    /**
     * Send email via PHP mail() function
     */
    private function send_via_mail($recipients, $subject, $body) {
        $headers = "MIME-Version: 1.0\r\n";
        $headers .= "Content-type: text/html; charset=UTF-8\r\n";
        $headers .= "From: {$this->from_name} <{$this->from_email}>\r\n";
        $headers .= "Reply-To: {$this->from_email}\r\n";
        
        $to = implode(',', $recipients);
        
        $ok = mail($to, $subject, $body, $headers);
        if (!$ok) {
            $this->last_error = 'PHP mail() failed';
        }
        return $ok;
    }
    
    /**
     * Send email via SMTP
     */
    private function send_via_smtp($recipients, $subject, $body) {
        try {
            $autoload = __DIR__ . '/../vendor/autoload.php';
            if (!file_exists($autoload)) {
                $this->last_error = 'PHPMailer not installed (vendor/autoload.php missing).';
                error_log($this->last_error);
                return false;
            }
            require_once $autoload;

            $mail = new PHPMailer\PHPMailer\PHPMailer(true);

            $debug_lines = [];
            $mail->SMTPDebug = 0;
            $mail->Debugoutput = function ($str, $level) use (&$debug_lines) {
                $debug_lines[] = trim((string)$str);
            };

            $mail->isSMTP();
            $mail->Host = $this->smtp_host;
            $mail->Port = (int)$this->smtp_port;

            if ($this->smtp_user !== '' || $this->smtp_pass !== '') {
                $mail->SMTPAuth = true;
                $mail->Username = $this->smtp_user;
                $mail->Password = $this->smtp_pass;
            }

            $enc = $this->smtp_encryption;
            if ($enc === null || $enc === '') {
                $enc = ((int)$this->smtp_port === 465) ? 'ssl' : 'tls';
            }
            $enc = strtolower((string)$enc);
            if ($enc === 'tls' || $enc === 'starttls') {
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            } elseif ($enc === 'ssl') {
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
            }

            $mail->setFrom($this->from_email, $this->from_name);
            foreach ($recipients as $recipient) {
                $recipient = trim((string)$recipient);
                if ($recipient !== '') {
                    $mail->addAddress($recipient);
                }
            }

            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body = $body;

            $mail->send();
            return true;
        } catch (Exception $e) {
            $msg = 'SMTP Error (PHPMailer): ' . $e->getMessage();
            if (!empty($debug_lines)) {
                $msg .= ' | Debug: ' . implode(' | ', array_slice($debug_lines, -20));
            }
            $this->last_error = $msg;
            error_log($msg);
            return false;
        }
    }
    
    /**
     * Test SMTP connection
     */
    public function test_connection() {
        try {
            $smtp = fsockopen($this->smtp_host, $this->smtp_port, $errno, $errstr, 5);
            
            if (!$smtp) {
                return [
                    'success' => false,
                    'error' => "Connection failed: $errstr ($errno)"
                ];
            }
            
            fclose($smtp);
            
            return [
                'success' => true,
                'message' => 'SMTP connection successful'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}

?>
