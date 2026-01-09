<?php
/**
 * Logout Page
 * Handles user logout and session termination
 */

session_start();
require_once '../config/config.php';
require_once '../includes/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Perform logout
logout();

// Redirect to login
redirect(LOGIN_URL);
