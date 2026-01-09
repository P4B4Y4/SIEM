<?php
/**
 * Database Connection Handler
 * Manages all database operations
 */

class Database {
    private static $instance = null;
    private $connection = null;
    private $error = null;

    private function __construct() {
        $this->connect();
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function connect() {
        try {
            $this->connection = new mysqli(
                DB_HOST,
                DB_USER,
                DB_PASS,
                DB_NAME,
                DB_PORT
            );

            if ($this->connection->connect_error) {
                throw new Exception("Connection failed: " . $this->connection->connect_error);
            }

            $this->connection->set_charset("utf8mb4");
        } catch (Exception $e) {
            $this->error = $e->getMessage();
            $this->logError($this->error);
        }
    }

    public function getConnection() {
        if ($this->connection === null || !$this->connection->ping()) {
            $this->connect();
        }
        return $this->connection;
    }

    public function query($sql) {
        $conn = $this->getConnection();
        if (!$conn) {
            return false;
        }

        $result = $conn->query($sql);
        if (!$result) {
            $this->error = $conn->error;
            $this->logError("Query Error: " . $this->error . " | SQL: " . $sql);
            return false;
        }
        return $result;
    }

    public function prepare($sql) {
        $conn = $this->getConnection();
        if (!$conn) {
            return false;
        }
        return $conn->prepare($sql);
    }

    public function escape($string) {
        $conn = $this->getConnection();
        if (!$conn) {
            return addslashes($string);
        }
        return $conn->real_escape_string($string);
    }

    public function getLastInsertId() {
        $conn = $this->getConnection();
        return $conn ? $conn->insert_id : 0;
    }

    public function getError() {
        return $this->error;
    }

    private function logError($message) {
        $logFile = LOG_DIR . 'database.log';
        $timestamp = date('Y-m-d H:i:s');
        error_log("[$timestamp] $message\n", 3, $logFile);
    }

    public function close() {
        if ($this->connection) {
            $this->connection->close();
            $this->connection = null;
        }
    }

    public function __destruct() {
        $this->close();
    }
}

// Helper function
function getDatabase() {
    return Database::getInstance();
}