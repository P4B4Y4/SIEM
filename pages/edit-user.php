<?php
session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';

check_login();
// check_role('admin'); // Temporarily disable for testing

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
$user = ['user_id' => '', 'username' => '', 'email' => '', 'role' => 'user', 'status' => 'active', 'mfa_email_enabled' => 0];
$is_editing = false;

function user_table_has_mfa_email_enabled($db) {
    $res = $db->query("SHOW COLUMNS FROM users LIKE 'mfa_email_enabled'");
    return ($res && $res->num_rows > 0);
}

if (isset($_GET['id'])) {
    $is_editing = true;
    if (user_table_has_mfa_email_enabled($db)) {
        $stmt = $db->prepare("SELECT user_id, username, email, role, status, mfa_email_enabled FROM users WHERE user_id = ?");
    } else {
        $stmt = $db->prepare("SELECT user_id, username, email, role, status, 0 AS mfa_email_enabled FROM users WHERE user_id = ?");
    }
    $stmt->bind_param('i', $_GET['id']);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $role = $_POST['role'];
    $status = $_POST['status'];
    $password = $_POST['password'];
    $mfa_email_enabled = isset($_POST['mfa_email_enabled']) ? 1 : 0;

    if ($is_editing) {
        $user_id = $_POST['user_id'];
        if (!empty($password)) {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("UPDATE users SET username = ?, email = ?, role = ?, status = ?, mfa_email_enabled = ?, password_hash = ? WHERE user_id = ?");
            $stmt->bind_param('ssssisi', $username, $email, $role, $status, $mfa_email_enabled, $password_hash, $user_id);
        } else {
            $stmt = $db->prepare("UPDATE users SET username = ?, email = ?, role = ?, status = ?, mfa_email_enabled = ? WHERE user_id = ?");
            $stmt->bind_param('sssiii', $username, $email, $role, $status, $mfa_email_enabled, $user_id);
        }
    } else {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, email, role, status, mfa_email_enabled, password_hash) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param('ssssis', $username, $email, $role, $status, $mfa_email_enabled, $password_hash);
    }

    $stmt->execute();
    header('Location: user-management.php');
    exit;
}
?>

<div class="container-fluid">
    <h1 class="mt-4"><?php echo $is_editing ? 'Edit User' : 'Add New User'; ?></h1>
    <form action="" method="POST">
        <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['user_id']); ?>">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>
        </div>
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" id="password" name="password" <?php echo $is_editing ? '' : 'required'; ?>>
            <?php if ($is_editing): ?>
                <small class="form-text text-muted">Leave blank to keep the current password.</small>
            <?php endif; ?>
        </div>
        <div class="form-group">
            <label for="role">Role</label>
            <select class="form-control" id="role" name="role">
                <option value="user" <?php echo $user['role'] === 'user' ? 'selected' : ''; ?>>User</option>
                <option value="admin" <?php echo $user['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
            </select>
        </div>
        <div class="form-group">
            <label for="status">Status</label>
            <select class="form-control" id="status" name="status">
                <option value="active" <?php echo $user['status'] === 'active' ? 'selected' : ''; ?>>Active</option>
                <option value="inactive" <?php echo $user['status'] === 'inactive' ? 'selected' : ''; ?>>Inactive</option>
            </select>
        </div>
        <div class="form-group">
            <label>
                <input type="checkbox" name="mfa_email_enabled" value="1" <?php echo (!empty($user['mfa_email_enabled']) ? 'checked' : ''); ?>>
                Enable Email MFA (OTP)
            </label>
        </div>
        <button type="submit" class="btn btn-primary">Save User</button>
    </form>
</div>

<?php include '../includes/footer.php'; ?>
