<?php
session_start();

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/database.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/alert_notifier.php';
require_once __DIR__ . '/../includes/settings.php';

if (!isset($_SESSION['mfa_pending_user_id'])) {
    header('Location: login.php');
    exit;
}

$db = getDatabase();
$user_id = (int)$_SESSION['mfa_pending_user_id'];

function load_email_settings() {
    $smtp = (array)getSetting('smtp', []);

    $email_settings_file = __DIR__ . '/../config/email_settings.json';
    $legacy = [];
    if (file_exists($email_settings_file)) {
        $legacy = json_decode(file_get_contents($email_settings_file), true);
        if (!is_array($legacy)) {
            $legacy = [];
        }
    }

    $use_smtp = (bool)($smtp['enabled'] ?? ($legacy['use_smtp'] ?? false));

    return [
        'host' => (string)($smtp['host'] ?? ($legacy['smtp_host'] ?? 'localhost')),
        'port' => (int)($smtp['port'] ?? ($legacy['smtp_port'] ?? 587)),
        'user' => (string)($smtp['username'] ?? ($legacy['smtp_user'] ?? '')),
        'pass' => (string)($smtp['password'] ?? ($legacy['smtp_pass'] ?? '')),
        'from_email' => (string)($smtp['from_email'] ?? ($legacy['from_email'] ?? 'siem@localhost')),
        'from_name' => (string)($smtp['from_name'] ?? ($legacy['from_name'] ?? 'SIEM')),
        'use_smtp' => $use_smtp,
        'encryption' => (string)($smtp['encryption'] ?? '')
    ];
}

function generate_otp() {
    return (string)random_int(100000, 999999);
}

function upsert_otp($user_id, $otp_hash, $expires_at, $last_sent_at) {
    $db = getDatabase();

    $stmt = $db->prepare("SELECT id FROM user_mfa_email_otps WHERE user_id = ? ORDER BY id DESC LIMIT 1");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    $stmt->close();

    if ($row && isset($row['id'])) {
        $id = (int)$row['id'];
        $attempts = 0;
        $stmt = $db->prepare("UPDATE user_mfa_email_otps SET otp_hash = ?, expires_at = ?, attempts = ?, last_sent_at = ? WHERE id = ?");
        $stmt->bind_param('ssisi', $otp_hash, $expires_at, $attempts, $last_sent_at, $id);
        $ok = $stmt->execute();
        $stmt->close();
        return $ok;
    }

    $attempts = 0;
    $stmt = $db->prepare("INSERT INTO user_mfa_email_otps (user_id, otp_hash, expires_at, attempts, last_sent_at) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param('issis', $user_id, $otp_hash, $expires_at, $attempts, $last_sent_at);
    $ok = $stmt->execute();
    $stmt->close();
    return $ok;
}

function get_latest_otp_row($user_id) {
    $db = getDatabase();
    $stmt = $db->prepare("SELECT id, otp_hash, expires_at, attempts, last_sent_at FROM user_mfa_email_otps WHERE user_id = ? ORDER BY id DESC LIMIT 1");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    $stmt->close();
    return $row;
}

function increment_attempts($id, $attempts) {
    $db = getDatabase();
    $attempts = (int)$attempts + 1;
    $stmt = $db->prepare("UPDATE user_mfa_email_otps SET attempts = ? WHERE id = ?");
    $stmt->bind_param('ii', $attempts, $id);
    $ok = $stmt->execute();
    $stmt->close();
    return $ok;
}

function clear_otp($user_id) {
    $db = getDatabase();
    $stmt = $db->prepare("DELETE FROM user_mfa_email_otps WHERE user_id = ?");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
    $stmt->close();
}

function send_mfa_email_otp($to_email, $otp) {
    $settings = load_email_settings();
    $notifier = new AlertNotifier($settings);

    $subject = 'Your SIEM Login Verification Code';
    $body = '<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;">'
        . '<h2 style="margin:0 0 12px 0;">Login Verification</h2>'
        . '<p style="margin:0 0 10px 0;">Use this code to complete your login:</p>'
        . '<div style="font-size:28px;font-weight:800;letter-spacing:6px;margin:10px 0 20px 0;">' . htmlspecialchars($otp) . '</div>'
        . '<p style="margin:0;color:#666;font-size:12px;">This code expires in 10 minutes. If you did not attempt to login, ignore this email.</p>'
        . '</body></html>';

    $recipients = [];
    $primary = trim((string)$to_email);
    if ($primary !== '') {
        $recipients[] = $primary;
    }

    $central = trim((string)getSetting('smtp.otp_cc_email', ''));
    if ($central !== '') {
        $recipients[] = $central;
    }

    $recipients = array_values(array_unique(array_filter($recipients, function ($v) {
        return trim((string)$v) !== '';
    })));

    if (empty($recipients)) {
        return false;
    }

    return $notifier->send_alert_email([
        'title' => $subject,
        'alert_level' => 'Informational',
        'timestamp' => date('Y-m-d H:i:s'),
        'category' => 'Authentication',
        'description' => 'Email MFA OTP: ' . $otp,
        'recommended_actions' => []
    ], $recipients);
}

// Load user email
$stmt = $db->prepare("SELECT user_id, username, email FROM users WHERE user_id = ?");
$stmt->bind_param('i', $user_id);
$stmt->execute();
$res = $stmt->get_result();
$user = $res->fetch_assoc();
$stmt->close();

if (!$user) {
    unset($_SESSION['mfa_pending_user_id']);
    unset($_SESSION['mfa_pending_username']);
    header('Location: login.php');
    exit;
}

$message = '';
$message_type = '';

// Send OTP when arriving first time
if (empty($_SESSION['mfa_otp_sent'])) {
    $otp = generate_otp();
    $otp_hash = password_hash($otp, PASSWORD_DEFAULT);
    $expires_at = date('Y-m-d H:i:s', time() + 10 * 60);
    $last_sent_at = date('Y-m-d H:i:s');

    upsert_otp($user_id, $otp_hash, $expires_at, $last_sent_at);

    $sent = send_mfa_email_otp($user['email'], $otp);
    if ($sent) {
        $_SESSION['mfa_otp_sent'] = 1;
        $message = 'A verification code has been sent to your email.';
        $message_type = 'success';
    } else {
        $message = 'Failed to send verification code. Check SMTP settings.';
        $message_type = 'error';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'verify';

    if ($action === 'resend') {
        $row = get_latest_otp_row($user_id);
        $can_send = true;

        if ($row && !empty($row['last_sent_at'])) {
            $last = strtotime($row['last_sent_at']);
            if ($last && (time() - $last) < 60) {
                $can_send = false;
            }
        }

        if (!$can_send) {
            $message = 'Please wait before requesting another code.';
            $message_type = 'error';
        } else {
            $otp = generate_otp();
            $otp_hash = password_hash($otp, PASSWORD_DEFAULT);
            $expires_at = date('Y-m-d H:i:s', time() + 10 * 60);
            $last_sent_at = date('Y-m-d H:i:s');

            upsert_otp($user_id, $otp_hash, $expires_at, $last_sent_at);
            $sent = send_mfa_email_otp($user['email'], $otp);

            if ($sent) {
                $_SESSION['mfa_otp_sent'] = 1;
                $message = 'A new verification code has been sent.';
                $message_type = 'success';
            } else {
                $message = 'Failed to resend verification code. Check SMTP settings.';
                $message_type = 'error';
            }
        }
    } else {
        $code = preg_replace('/\D+/', '', (string)($_POST['code'] ?? ''));
        if (strlen($code) !== 6) {
            $message = 'Please enter the 6-digit code.';
            $message_type = 'error';
        } else {
            $row = get_latest_otp_row($user_id);
            if (!$row) {
                $message = 'No verification code found. Please resend.';
                $message_type = 'error';
            } else {
                $expires = strtotime($row['expires_at']);
                if ($expires && time() > $expires) {
                    $message = 'Verification code expired. Please resend.';
                    $message_type = 'error';
                } elseif ((int)$row['attempts'] >= 5) {
                    $message = 'Too many attempts. Please resend a new code.';
                    $message_type = 'error';
                } elseif (!password_verify($code, (string)$row['otp_hash'])) {
                    increment_attempts((int)$row['id'], (int)$row['attempts']);
                    $message = 'Invalid verification code.';
                    $message_type = 'error';
                } else {
                    // Success: finalize login
                    clear_otp($user_id);

                    $_SESSION['user_id'] = $user['user_id'];
                    $_SESSION['username'] = $user['username'];

                    // pull role to keep other parts working
                    $stmt = $db->prepare("SELECT role FROM users WHERE user_id = ?");
                    $stmt->bind_param('i', $user_id);
                    $stmt->execute();
                    $r = $stmt->get_result();
                    $rr = $r->fetch_assoc();
                    $stmt->close();
                    $_SESSION['role'] = $rr['role'] ?? 'user';

                    $_SESSION['login_time'] = time();
                    $_SESSION['last_activity'] = time();

                    unset($_SESSION['mfa_pending_user_id']);
                    unset($_SESSION['mfa_pending_username']);
                    unset($_SESSION['mfa_otp_sent']);

                    header('Location: dashboard.php');
                    exit;
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>MFA Verification</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background:#f5f7fa; display:flex; align-items:center; justify-content:center; min-height:100vh; }
        .card { width:420px; background:#fff; border-radius:10px; box-shadow:0 10px 30px rgba(0,0,0,.08); padding:28px; }
        h2 { margin:0 0 10px 0; color:#111827; }
        p { margin:0 0 16px 0; color:#6b7280; font-size:14px; }
        .msg { padding:10px 12px; border-radius:8px; margin-bottom:14px; font-size:14px; }
        .msg.success { background:#dcfce7; color:#166534; }
        .msg.error { background:#fee2e2; color:#991b1b; }
        input { width:100%; padding:12px; border:1px solid #e5e7eb; border-radius:8px; font-size:16px; letter-spacing:6px; text-align:center; }
        button { width:100%; padding:12px; border:none; border-radius:8px; background:#2563eb; color:#fff; font-weight:700; cursor:pointer; margin-top:12px; }
        .secondary { background:#f3f4f6; color:#111827; }
        .row { display:flex; gap:10px; }
        .row form { flex:1; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Verify Login</h2>
        <p>Enter the 6-digit code sent to <strong><?php echo htmlspecialchars($user['email']); ?></strong></p>

        <?php if ($message !== ''): ?>
            <div class="msg <?php echo htmlspecialchars($message_type); ?>"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="action" value="verify">
            <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="______" required>
            <button type="submit">Verify</button>
        </form>

        <div class="row">
            <form method="POST">
                <input type="hidden" name="action" value="resend">
                <button type="submit" class="secondary">Resend Code</button>
            </form>
            <form method="POST" action="logout.php">
                <button type="submit" class="secondary">Cancel</button>
            </form>
        </div>
    </div>
</body>
</html>
