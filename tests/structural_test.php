<?php
/**
 * Structural Test Suite
 * Validates folder structure, file existence, and code integrity
 */

class StructuralTest {
    private $basePath = __DIR__ . '/..';
    private $results = [];
    private $passed = 0;
    private $failed = 0;

    public function run() {
        echo "=== STRUCTURAL TEST SUITE ===\n\n";

        $this->testFolderStructure();
        $this->testFileExistence();
        $this->testFilePermissions();
        $this->testPhpSyntax();
        $this->testConfigurationFiles();

        $this->printResults();
    }

    private function testFolderStructure() {
        echo "[FOLDER STRUCTURE]\n";

        $requiredFolders = [
            'pages',
            'includes',
            'assets',
            'config',
            'logs',
            'tests'
        ];

        foreach ($requiredFolders as $folder) {
            $path = $this->basePath . '/' . $folder;
            if (is_dir($path)) {
                $this->pass("Folder exists: $folder");
            } else {
                $this->fail("Folder missing: $folder");
            }
        }
        echo "\n";
    }

    private function testFileExistence() {
        echo "[FILE EXISTENCE]\n";

        $requiredFiles = [
            'config/config.php',
            'includes/database.php',
            'includes/auth.php',
            'includes/functions.php',
            'pages/login.php',
            'pages/dashboard.php',
            'pages/logout.php',
            'tests/structural_test.php',
            'tests/functional_test.php'
        ];

        foreach ($requiredFiles as $file) {
            $path = $this->basePath . '/' . $file;
            if (file_exists($path)) {
                $size = filesize($path);
                $this->pass("File exists: $file ($size bytes)");
            } else {
                $this->fail("File missing: $file");
            }
        }
        echo "\n";
    }

    private function testFilePermissions() {
        echo "[FILE PERMISSIONS]\n";

        $files = [
            'config/config.php' => 'readable',
            'includes/database.php' => 'readable',
            'pages/login.php' => 'readable',
            'logs' => 'writable'
        ];

        foreach ($files as $file => $permission) {
            $path = $this->basePath . '/' . $file;
            
            if ($permission === 'readable' && is_readable($path)) {
                $this->pass("File readable: $file");
            } elseif ($permission === 'writable' && is_writable($path)) {
                $this->pass("Directory writable: $file");
            } else {
                $this->fail("Permission issue: $file ($permission)");
            }
        }
        echo "\n";
    }

    private function testPhpSyntax() {
        echo "[PHP SYNTAX VALIDATION]\n";

        $phpFiles = [
            'config/config.php',
            'includes/database.php',
            'includes/auth.php',
            'includes/functions.php',
            'pages/login.php',
            'pages/dashboard.php',
            'pages/logout.php'
        ];

        foreach ($phpFiles as $file) {
            $path = $this->basePath . '/' . $file;
            $output = shell_exec("php -l " . escapeshellarg($path) . " 2>&1");
            
            if (strpos($output, 'No syntax errors') !== false) {
                $this->pass("PHP syntax valid: $file");
            } else {
                $this->fail("PHP syntax error in $file: " . trim($output));
            }
        }
        echo "\n";
    }

    private function testConfigurationFiles() {
        echo "[CONFIGURATION FILES]\n";

        $configFile = $this->basePath . '/config/config.php';
        
        if (file_exists($configFile)) {
            include $configFile;
            
            $requiredConstants = [
                'APP_NAME',
                'APP_VERSION',
                'DB_HOST',
                'DB_NAME',
                'DB_USER',
                'SESSION_TIMEOUT',
                'BASE_URL',
                'LOGIN_URL',
                'DASHBOARD_URL'
            ];

            foreach ($requiredConstants as $constant) {
                if (defined($constant)) {
                    $value = constant($constant);
                    $this->pass("Constant defined: $constant = " . (is_string($value) ? "'$value'" : $value));
                } else {
                    $this->fail("Constant missing: $constant");
                }
            }
        } else {
            $this->fail("Configuration file not found");
        }
        echo "\n";
    }

    private function pass($message) {
        echo "✓ PASS: $message\n";
        $this->passed++;
    }

    private function fail($message) {
        echo "✗ FAIL: $message\n";
        $this->failed++;
    }

    private function printResults() {
        echo "\n=== TEST RESULTS ===\n";
        echo "Passed: " . $this->passed . "\n";
        echo "Failed: " . $this->failed . "\n";
        echo "Total:  " . ($this->passed + $this->failed) . "\n";
        echo "Status: " . ($this->failed === 0 ? "✓ ALL TESTS PASSED" : "✗ SOME TESTS FAILED") . "\n";
    }
}

// Run tests
$test = new StructuralTest();
$test->run();
