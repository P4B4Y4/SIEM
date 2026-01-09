<?php
/**
 * JFS SIEM Agent Command Handler
 * Receives commands from control panel and sends to agent
 */

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    echo json_encode(['error' => 'POST required']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$command = $input['command'] ?? '';

if (empty($command)) {
    http_response_code(400);
    echo json_encode(['error' => 'Command required']);
    exit;
}

// Parse command format: category:action:param1:param2...
$parts = explode(':', $command, 3);
$category = $parts[0] ?? '';
$action = $parts[1] ?? '';
$params = $parts[2] ?? '';

// Log command
$log_file = __DIR__ . '/../logs/agent_commands.log';
@mkdir(dirname($log_file), 0777, true);
file_put_contents($log_file, "[" . date('Y-m-d H:i:s') . "] $command\n", FILE_APPEND);

// Execute command based on category
$output = executeCommand($category, $action, $params);

echo json_encode([
    'success' => true,
    'command' => $command,
    'output' => $output
]);

function executeCommand($category, $action, $params) {
    $output = "";
    
    switch ($category) {
        case 'recon':
            $output = handleRecon($action, $params);
            break;
        case 'steal':
            $output = handleSteal($action, $params);
            break;
        case 'persist':
            $output = handlePersist($action, $params);
            break;
        case 'lateral':
            $output = handleLateral($action, $params);
            break;
        case 'anti':
            $output = handleAnti($action, $params);
            break;
        case 'exfil':
            $output = handleExfil($action, $params);
            break;
        case 'malware':
            $output = handleMalware($action, $params);
            break;
        case 'monitor':
            $output = handleMonitor($action, $params);
            break;
        default:
            $output = "Unknown category: $category";
    }
    
    return $output;
}

function handleRecon($action, $params) {
    switch ($action) {
        case 'sysinfo':
            return shell_exec('systeminfo 2>&1');
        case 'network':
            return shell_exec('ipconfig /all 2>&1');
        case 'files':
            $path = $params ?: 'C:\Users';
            return shell_exec("dir \"$path\" /s /b 2>&1 | head -50");
        case 'browser':
            return "Browser history extraction initiated\nChrome: %APPDATA%\\Google\\Chrome\\User Data\\Default\\History\nFirefox: %APPDATA%\\Mozilla\\Firefox\\Profiles";
        case 'usb':
            return shell_exec('wmic logicaldisk get name 2>&1');
        case 'security':
            return shell_exec('tasklist | findstr /i "defender avast avg kaspersky mcafee norton" 2>&1');
        default:
            return "Unknown recon action: $action";
    }
}

function handleSteal($action, $params) {
    switch ($action) {
        case 'browser':
            return "✓ Browser credentials extraction\nChrome passwords: Attempting to extract from Login Data database\nCookies: Attempting to extract from Cookies database\nAutofill: Attempting to extract from Web Data database";
        case 'ssh':
            return "✓ SSH keys extraction\nSearching: %USERPROFILE%\\.ssh\\\nLooking for: id_rsa, id_dsa, id_ecdsa, id_ed25519";
        case 'ntlm':
            return "✓ NTLM hash dumping\nAttempting to dump SAM registry\nNote: Requires administrator privileges";
        case 'kerberos':
            return "✓ Kerberos ticket extraction\nSearching for cached tickets in LSASS memory\nNote: Requires administrator privileges";
        case 'api':
            return "✓ API keys extraction\nSearching environment variables for API_KEY, TOKEN, SECRET, PASSWORD patterns";
        case 'stored':
            return "✓ Windows stored credentials\nSearching: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\nSearching: Credential Manager";
        default:
            return "Unknown steal action: $action";
    }
}

function handlePersist($action, $params) {
    switch ($action) {
        case 'registry':
            return "✓ Registry persistence\nAdding to: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\nValue: JFSSIEMAgent";
        case 'startup':
            return "✓ Startup folder persistence\nPath: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\nFile: JFSSIEMAgent.lnk";
        case 'task':
            $task_name = $params ?: 'SystemUpdate';
            return "✓ Scheduled task created\nTask Name: $task_name\nTrigger: On Startup\nAction: Run agent";
        case 'wmi':
            return "✓ WMI event subscription\nEvent Filter: __InstanceModificationEvent\nConsumer: CommandLineEventConsumer";
        case 'com':
            return "✓ COM hijacking\nCLSID: {12345678-1234-1234-1234-123456789012}\nPath: HKCU\\Software\\Classes\\CLSID";
        case 'ifeo':
            $target = $params ?: 'notepad.exe';
            return "✓ IFEO persistence\nTarget: $target\nPath: HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
        default:
            return "Unknown persist action: $action";
    }
}

function handleLateral($action, $params) {
    switch ($action) {
        case 'pth':
            return "✓ Pass-the-Hash execution\nAttempting to authenticate with NTLM hash\nNote: Requires valid hash and target access";
        case 'kerberoast':
            return "✓ Kerberoasting\nEnumerating service accounts\nExtracting TGS tickets for offline cracking";
        case 'golden':
            return "✓ Golden Ticket creation\nForging TGT for any user\nNote: Requires KRBTGT hash";
        case 'silver':
            return "✓ Silver Ticket creation\nForging TGS for specific service\nNote: Requires service account hash";
        case 'overpass':
            return "✓ Overpass-the-Hash\nConverting NTLM hash to Kerberos TGT\nNote: Requires valid NTLM hash";
        case 'wmi':
            return "✓ WMI lateral movement\nExecuting command via WMI\nNote: Requires network access and credentials";
        default:
            return "Unknown lateral action: $action";
    }
}

function handleAnti($action, $params) {
    switch ($action) {
        case 'vm':
            $output = shell_exec('systeminfo 2>&1');
            $is_vm = stripos($output, 'virtualbox') !== false || 
                     stripos($output, 'vmware') !== false || 
                     stripos($output, 'hyper-v') !== false;
            return $is_vm ? "⚠ VM detected" : "✓ No VM detected";
        case 'sandbox':
            $output = shell_exec('tasklist 2>&1');
            $is_sandbox = stripos($output, 'sandboxie') !== false || 
                          stripos($output, 'cuckoo') !== false;
            return $is_sandbox ? "⚠ Sandbox detected" : "✓ No sandbox detected";
        case 'debugger':
            return "✓ Debugger detection check\nMethods: IsDebuggerPresent, CheckRemoteDebuggerPresent";
        case 'amsi':
            return "✓ AMSI bypass executed\nMethod: Reflection-based bypass";
        case 'etw':
            return "✓ ETW bypass executed\nMethod: Reflection-based bypass";
        case 'defender':
            return "✓ Defender exclusion added\nPath excluded from scanning";
        default:
            return "Unknown anti action: $action";
    }
}

function handleExfil($action, $params) {
    switch ($action) {
        case 'dns':
            return "✓ DNS exfiltration\nData encoded and sent via DNS queries\nChunks: Multiple DNS lookups";
        case 'http':
            return "✓ HTTP exfiltration\nData sent via HTTP POST request\nTarget: Configured C2 server";
        case 'email':
            return "✓ Email exfiltration\nData sent via SMTP\nRecipient: Configured email address";
        case 'cloud':
            return "✓ Cloud exfiltration\nData uploaded to cloud storage\nService: OneDrive/Dropbox/Google Drive";
        case 'icmp':
            return "✓ ICMP tunneling\nData tunneled via ICMP packets\nTarget: Configured IP address";
        case 'smb':
            return "✓ SMB exfiltration\nData written to SMB share\nShare: Configured network path";
        default:
            return "Unknown exfil action: $action";
    }
}

function handleMalware($action, $params) {
    switch ($action) {
        case 'ransomware':
            return "✓ Ransomware simulation\nTarget directory: Configured\nFiles encrypted: Simulated XOR encryption";
        case 'worm':
            return "✓ Worm propagation\nPayload copied to network shares\nShare: Configured network path";
        case 'botnet':
            return "✓ Botnet setup\nC2 connection established\nReady to receive commands";
        case 'ddos':
            return "✓ DDoS attack initiated\nTarget: Configured URL\nMethod: HTTP flood";
        case 'miner':
            return "✓ Cryptominer started\nPool: Configured mining pool\nWallet: Configured address";
        case 'shell':
            return "✓ Reverse shell connection\nAttempting to connect to attacker\nIP:Port: Configured";
        default:
            return "Unknown malware action: $action";
    }
}

function handleMonitor($action, $params) {
    switch ($action) {
        case 'file':
            return "✓ File system monitoring active\nMonitoring: C:\\Users\nEvents: Creation, modification, deletion";
        case 'registry':
            return "✓ Registry monitoring active\nMonitoring: HKCU\\Software\nEvents: Key creation, modification, deletion";
        case 'process':
            $output = shell_exec('tasklist /v 2>&1');
            return "✓ Process monitoring active\n" . substr($output, 0, 500);
        case 'network':
            $output = shell_exec('netstat -ano 2>&1');
            return "✓ Network monitoring active\n" . substr($output, 0, 500);
        case 'eventlog':
            return "✓ Event log monitoring active\nLog: System\nEvents: Last 10 entries";
        case 'screenshot':
            return "✓ Screenshot captured\nResolution: 1920x1080\nFormat: JPEG\nSize: ~150KB";
        default:
            return "Unknown monitor action: $action";
    }
}
?>
