<?php
/**
 * Settings Helper Module
 * Functions for application settings management
 */

class SettingsManager {
    private static $settings = null;
    private static $settingsFile = null;

    public static function init() {
        self::$settingsFile = __DIR__ . '/../config/settings.json';
        self::loadSettings();
    }

    private static function loadSettings() {
        if (file_exists(self::$settingsFile)) {
            $json = file_get_contents(self::$settingsFile);
            self::$settings = json_decode($json, true) ?? [];
        } else {
            self::$settings = [];
        }
    }

    public static function get($key, $default = null) {
        if (self::$settings === null) {
            self::loadSettings();
        }
        
        // Support dot notation (e.g., 'database.host')
        if (strpos($key, '.') !== false) {
            $parts = explode('.', $key);
            $value = self::$settings;
            
            foreach ($parts as $part) {
                if (isset($value[$part])) {
                    $value = $value[$part];
                } else {
                    return $default;
                }
            }
            
            return $value;
        }
        
        return self::$settings[$key] ?? $default;
    }

    public static function set($key, $value) {
        if (self::$settings === null) {
            self::loadSettings();
        }
        
        // Support dot notation
        if (strpos($key, '.') !== false) {
            $parts = explode('.', $key);
            $current = &self::$settings;
            
            foreach ($parts as $i => $part) {
                if ($i === count($parts) - 1) {
                    $current[$part] = $value;
                } else {
                    if (!isset($current[$part])) {
                        $current[$part] = [];
                    }
                    $current = &$current[$part];
                }
            }
        } else {
            self::$settings[$key] = $value;
        }
        
        return self::save();
    }

    public static function save() {
        if (self::$settings === null) {
            return false;
        }
        
        $json = json_encode(self::$settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        return file_put_contents(self::$settingsFile, $json) !== false;
    }

    public static function getAll() {
        if (self::$settings === null) {
            self::loadSettings();
        }
        return self::$settings;
    }

    public static function delete($key) {
        if (self::$settings === null) {
            self::loadSettings();
        }
        
        if (isset(self::$settings[$key])) {
            unset(self::$settings[$key]);
            return self::save();
        }
        
        return false;
    }
}

// Initialize settings manager
SettingsManager::init();

/**
 * Get setting value
 */
function getSetting($key, $default = null) {
    return SettingsManager::get($key, $default);
}

/**
 * Set setting value
 */
function setSetting($key, $value) {
    return SettingsManager::set($key, $value);
}

/**
 * Get all settings
 */
function getAllSettings() {
    return SettingsManager::getAll();
}

/**
 * Delete setting
 */
function deleteSetting($key) {
    return SettingsManager::delete($key);
}

/**
 * Test database connection
 */
function testDatabaseConnection($host, $user, $pass, $name) {
    try {
        $conn = new mysqli($host, $user, $pass, $name);
        
        if ($conn->connect_error) {
            return [
                'success' => false,
                'message' => 'Connection failed: ' . $conn->connect_error
            ];
        }
        
        $conn->close();
        
        return [
            'success' => true,
            'message' => 'Database connection successful'
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ];
    }
}

/**
 * Test email connection
 */
function testEmailConnection($host, $port, $user, $pass) {
    try {
        // This is a simplified test - in production use PHPMailer or similar
        $fp = @fsockopen($host, $port, $errno, $errstr, 5);
        
        if (!$fp) {
            return [
                'success' => false,
                'message' => "Connection failed: $errstr ($errno)"
            ];
        }
        
        fclose($fp);
        
        return [
            'success' => true,
            'message' => 'Email server connection successful'
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ];
    }
}

/**
 * Get backup status
 */
function getBackupStatus() {
    $backupPath = getSetting('backup.path', LOG_DIR . 'backups/');
    
    if (!is_dir($backupPath)) {
        return [
            'exists' => false,
            'count' => 0,
            'last_backup' => null,
            'total_size' => 0
        ];
    }
    
    $files = glob($backupPath . '*.sql');
    $totalSize = 0;
    $lastModified = 0;
    
    foreach ($files as $file) {
        $totalSize += filesize($file);
        $mtime = filemtime($file);
        if ($mtime > $lastModified) {
            $lastModified = $mtime;
        }
    }
    
    return [
        'exists' => true,
        'count' => count($files),
        'last_backup' => $lastModified ? date('M d, Y H:i:s', $lastModified) : null,
        'total_size' => formatBytes($totalSize)
    ];
}

/**
 * Create backup
 */
function createBackup() {
    $db = getDatabase();
    $conn = $db->getConnection();
    
    if (!$conn) {
        return [
            'success' => false,
            'message' => 'Database connection failed'
        ];
    }
    
    try {
        $backupPath = getSetting('backup.path', LOG_DIR . 'backups/');
        
        if (!is_dir($backupPath)) {
            mkdir($backupPath, 0755, true);
        }
        
        $filename = $backupPath . 'backup_' . date('Y-m-d_H-i-s') . '.sql';
        
        // Simple backup using mysqldump
        $command = sprintf(
            'mysqldump -h %s -u %s -p%s %s > %s',
            escapeshellarg(DB_HOST),
            escapeshellarg(DB_USER),
            escapeshellarg(DB_PASS),
            escapeshellarg(DB_NAME),
            escapeshellarg($filename)
        );
        
        exec($command, $output, $return_var);
        
        if ($return_var === 0) {
            return [
                'success' => true,
                'message' => 'Backup created successfully',
                'file' => basename($filename),
                'size' => formatBytes(filesize($filename))
            ];
        } else {
            return [
                'success' => false,
                'message' => 'Backup failed'
            ];
        }
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ];
    }
}
