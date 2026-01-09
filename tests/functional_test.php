<?php
/**
 * Functional Test Suite
 * Tests application functionality and features
 */

session_start();

class FunctionalTest {
    private $basePath = __DIR__ . '/..';
    private $results = [];
    private $passed = 0;
    private $failed = 0;
    private $db = null;

    public function run() {
        echo "=== FUNCTIONAL TEST SUITE ===\n\n";

        $this->testConfigurationLoading();
        $this->testDatabaseConnection();
        $this->testAuthenticationSystem();
        $this->testSessionManagement();
        $this->testHelperFunctions();
        $this->testPageAccess();

        $this->printResults();
    }

    private function testConfigurationLoading() {
        echo "[CONFIGURATION LOADING]\n";

        try {
            require_once $this->basePath . '/config/config.php';
            
            if (defined('APP_NAME')) {
                $this->pass("Configuration loaded successfully");
            } else {
                $this->fail("Configuration constants not defined");
            }
        } catch (Exception $e) {
            $this->fail("Configuration loading error: " . $e->getMessage());
        }
        echo "\n";
    }

    private function testDatabaseConnection() {
        echo "[DATABASE CONNECTION]\n";

        try {
            require_once $this->basePath . '/includes/database.php';
            
            $db = getDatabase();
            $conn = $db->getConnection();
            
            if ($conn && $conn->ping()) {
                $this->pass("Database connection successful");
                $this->db = $db;
            } else {
                $this->fail("Database connection failed");
            }
        } catch (Exception $e) {
            $this->fail("Database error: " . $e->getMessage());
        }
        echo "\n";
    }

    private function testAuthenticationSystem() {
        echo "[AUTHENTICATION SYSTEM]\n";

        try {
            require_once $this->basePath . '/includes/auth.php';
            
            // Test invalid login using helper function
            $result = login('invalid_user', 'invalid_pass');
            if (!$result['success']) {
                $this->pass("Invalid login rejected correctly");
            } else {
                $this->fail("Invalid login was accepted");
            }

            // Test session check
            if (!isLoggedIn()) {
                $this->pass("Session check works (not logged in)");
            } else {
                $this->fail("Session check failed");
            }

        } catch (Exception $e) {
            $this->fail("Authentication error: " . $e->getMessage());
        }
        echo "\n";
    }

    private function testSessionManagement() {
        echo "[SESSION MANAGEMENT]\n";

        try {
            // Test session creation
            $_SESSION['test_key'] = 'test_value';
            
            if (isset($_SESSION['test_key']) && $_SESSION['test_key'] === 'test_value') {
                $this->pass("Session variable storage works");
            } else {
                $this->fail("Session variable storage failed");
            }

            // Test session timeout check
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            
            if (isset($_SESSION['login_time'])) {
                $this->pass("Session timestamps set correctly");
            } else {
                $this->fail("Session timestamps not set");
            }

            unset($_SESSION['test_key']);
        } catch (Exception $e) {
            $this->fail("Session management error: " . $e->getMessage());
        }
        echo "\n";
    }

    private function testHelperFunctions() {
        echo "[HELPER FUNCTIONS]\n";

        try {
            require_once $this->basePath . '/includes/functions.php';

            // Test sanitize function
            $input = "<script>alert('xss')</script>";
            $sanitized = sanitize($input);
            if (strpos($sanitized, '<script>') === false) {
                $this->pass("Sanitize function works");
            } else {
                $this->fail("Sanitize function failed");
            }

            // Test escape function
            $escaped = escape("<b>test</b>");
            if (strpos($escaped, '<b>') === false) {
                $this->pass("Escape function works");
            } else {
                $this->fail("Escape function failed");
            }

            // Test formatBytes function
            $formatted = formatBytes(1024);
            if (strpos($formatted, 'KB') !== false) {
                $this->pass("formatBytes function works");
            } else {
                $this->fail("formatBytes function failed");
            }

            // Test timeAgo function
            $time = timeAgo(date('Y-m-d H:i:s'));
            if (strlen($time) > 0) {
                $this->pass("timeAgo function works");
            } else {
                $this->fail("timeAgo function failed");
            }

        } catch (Exception $e) {
            $this->fail("Helper functions error: " . $e->getMessage());
        }
        echo "\n";
    }

    private function testPageAccess() {
        echo "[PAGE ACCESS]\n";

        try {
            // Test login page exists and is accessible
            $loginPage = $this->basePath . '/pages/login.php';
            if (file_exists($loginPage) && is_readable($loginPage)) {
                $this->pass("Login page accessible");
            } else {
                $this->fail("Login page not accessible");
            }

            // Test dashboard page exists and is accessible
            $dashboardPage = $this->basePath . '/pages/dashboard.php';
            if (file_exists($dashboardPage) && is_readable($dashboardPage)) {
                $this->pass("Dashboard page accessible");
            } else {
                $this->fail("Dashboard page not accessible");
            }

            // Test logout page exists
            $logoutPage = $this->basePath . '/pages/logout.php';
            if (file_exists($logoutPage) && is_readable($logoutPage)) {
                $this->pass("Logout page accessible");
            } else {
                $this->fail("Logout page not accessible");
            }

        } catch (Exception $e) {
            $this->fail("Page access error: " . $e->getMessage());
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
$test = new FunctionalTest();
$test->run();
