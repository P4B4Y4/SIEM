<?php
$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

$result = $db->query("DELETE FROM remote_commands WHERE status = 'pending'");
$deleted = $db->affected_rows;

echo "Cleared $deleted pending commands\n";

$db->close();
?>
