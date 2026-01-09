<?php
/**
 * Authentication Handler
 * Manages user login, logout, and session management
 */

class Auth {
    private static $sessionTimeout = SESSION_TIMEOUT;
    private static $maxAttempts = MAX_LOGIN_ATTEMPTS;
    private static $lockoutDuration = LOCKOUT_DURATION;

    private static function hasUserColumn($columnName) {
        $db = getDatabase();
        $col = $db->escape((string)$columnName);
        $result = $db->query("SHOW COLUMNS FROM users LIKE '$col'");
        return ($result && $result->num_rows > 0);
    }

    public static function login($username, $password) {
        // Validate input
        if (empty($username) || empty($password)) {
            return ['success' => false, 'message' => 'Username and password required'];
        }

        // Check for account lockout
        if (self::isAccountLocked($username)) {
            return ['success' => false, 'message' => 'Account temporarily locked. Try again later.'];
        }

        // Get user from database
        $db = getDatabase();

        $select = "SELECT user_id, username, password_hash, role, status";
        if (self::hasUserColumn('mfa_email_enabled')) {
            $select .= ", mfa_email_enabled";
        } else {
            $select .= ", 0 AS mfa_email_enabled";
        }
        $select .= " FROM users WHERE username = ?";

        $stmt = $db->prepare($select);
        
        if (!$stmt) {
            return ['success' => false, 'message' => 'Database error'];
        }

        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if (!$user) {
            self::recordFailedAttempt($username);
            return ['success' => false, 'message' => 'Invalid username or password'];
        }

        // Check user status
        if ($user['status'] !== 'active') {
            return ['success' => false, 'message' => 'User account is inactive'];
        }

        // Verify password
        if (!password_verify($password, $user['password_hash'])) {
            self::recordFailedAttempt($username);
            return ['success' => false, 'message' => 'Invalid username or password'];
        }

        // Clear failed attempts
        self::clearFailedAttempts($username);

        // If email MFA is enabled, require step-up verification
        if (!empty($user['mfa_email_enabled'])) {
            $_SESSION['mfa_pending_user_id'] = $user['user_id'];
            $_SESSION['mfa_pending_username'] = $user['username'];
            unset($_SESSION['mfa_otp_sent']);
            return ['success' => true, 'mfa_required' => true, 'redirect' => 'mfa-verify.php'];
        }

        // Create session
        $_SESSION['user_id'] = $user['user_id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity'] = time();

        // Log login
        self::logActivity($user['user_id'], 'LOGIN', 'User logged in');

        return ['success' => true, 'message' => 'Login successful'];
    }

    public static function logout() {
        if (isset($_SESSION['user_id'])) {
            self::logActivity($_SESSION['user_id'], 'LOGOUT', 'User logged out');
        }
        
        session_destroy();
        return true;
    }

    public static function isLoggedIn() {
        if (!isset($_SESSION['user_id'])) {
            return false;
        }

        // Ensure last_activity exists for older sessions
        if (!isset($_SESSION['last_activity'])) {
            $_SESSION['last_activity'] = time();
            return true;
        }

        // Check session timeout
        if (time() - (int)$_SESSION['last_activity'] > self::$sessionTimeout) {
            self::logout();
            return false;
        }

        // Update last activity
        $_SESSION['last_activity'] = time();
        return true;
    }

    public static function getCurrentUser() {
        if (!self::isLoggedIn()) {
            return null;
        }

        $db = getDatabase();
        $stmt = $db->prepare("SELECT user_id, username, role, email, status FROM users WHERE user_id = ?");
        
        if (!$stmt) {
            return null;
        }

        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        return $user;
    }

    public static function hasRole($role) {
        if (!self::isLoggedIn()) {
            return false;
        }
        return $_SESSION['role'] === $role;
    }

    public static function isAdmin() {
        return self::hasRole('admin');
    }

    private static function isAccountLocked($username) {
        $lockFile = LOG_DIR . 'lockout_' . md5($username) . '.lock';
        
        if (!file_exists($lockFile)) {
            return false;
        }

        $lockTime = file_get_contents($lockFile);
        if (time() - $lockTime > self::$lockoutDuration) {
            unlink($lockFile);
            return false;
        }

        return true;
    }

    private static function recordFailedAttempt($username) {
        $attemptsFile = LOG_DIR . 'attempts_' . md5($username) . '.txt';
        $attempts = 1;

        if (file_exists($attemptsFile)) {
            $attempts = (int)file_get_contents($attemptsFile) + 1;
        }

        file_put_contents($attemptsFile, $attempts);

        if ($attempts >= self::$maxAttempts) {
            file_put_contents(LOG_DIR . 'lockout_' . md5($username) . '.lock', time());
        }
    }

    private static function clearFailedAttempts($username) {
        $attemptsFile = LOG_DIR . 'attempts_' . md5($username) . '.txt';
        if (file_exists($attemptsFile)) {
            unlink($attemptsFile);
        }
    }

    private static function logActivity($userId, $action, $details) {
        if (!defined('ENABLE_AUDIT_LOGGING') || !ENABLE_AUDIT_LOGGING) {
            return;
        }

        $logFile = LOG_DIR . 'audit.log';
        $timestamp = date('Y-m-d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
        $message = "[$timestamp] User: $userId | Action: $action | Details: $details | IP: $ip\n";
        error_log($message, 3, $logFile);
    }
}

// Helper functions
function login($username, $password) {
    return Auth::login($username, $password);
}

function check_login() {
    if (!Auth::isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}

function check_role($role) {
    check_login();
    if (!Auth::hasRole($role)) {
        http_response_code(403);
        echo 'Forbidden';
        exit;
    }
}

function logout() {
    return Auth::logout();
}

function isLoggedIn() {
    return Auth::isLoggedIn();
}

function getCurrentUser() {
    return Auth::getCurrentUser();
}

function isAdmin() {
    return Auth::isAdmin();
}
