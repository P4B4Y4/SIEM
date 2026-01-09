<?php
session_start();

require_once __DIR__ . '/config/config.sample.php';
if (file_exists(__DIR__ . '/config/config.local.php')) {
    require_once __DIR__ . '/config/config.local.php';
}
require_once __DIR__ . '/includes/database.php';
require_once __DIR__ . '/includes/auth.php';

if (isLoggedIn()) {
    header('Location: pages/dashboard.php');
    exit;
}

header('Location: pages/login.php');
exit;
