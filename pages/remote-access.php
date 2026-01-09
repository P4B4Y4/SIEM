<?php
/**
 * SIEM Remote Access Interface
 * Control remote PCs like AnyDesk
 */

session_start();

// Check if logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Database connection
$db = new mysqli('localhost', 'root', '', 'jfs_siem');

if ($db->connect_error) {
    die('Database connection failed: ' . $db->connect_error);
}

$agent = $_GET['agent'] ?? '';
?>
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Remote Access</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #1a1a1a; 
            color: #fff;
        }
        
        .container { display: flex; height: 100vh; }
        
        .sidebar {
            width: 250px;
            background: #0f0f0f;
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
            background: #222;
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
        
        .agent-name {
            font-weight: bold;
            font-size: 13px;
        }
        
        .agent-status {
            font-size: 11px;
            color: #999;
            margin-top: 4px;
        }
        
        .status-online { color: #00cc66; }
        .status-offline { color: #ff3333; }
        
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
        }
        
        .header p {
            font-size: 12px;
            opacity: 0.9;
        }
        
        .content {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding: 20px;
            overflow: hidden;
        }
        
        .screen-area {
            flex: 1;
            background: #000;
            border: 1px solid #333;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
            cursor: crosshair;
        }
        
        .screen-canvas {
            width: 100%;
            height: 100%;
            background: #1a1a1a;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #666;
        }
        
        .controls {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            padding: 15px;
            background: #222;
            border-radius: 4px;
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
        }
        
        .btn:hover {
            background: #004499;
        }
        
        .btn-danger {
            background: #ff3333;
        }
        
        .btn-danger:hover {
            background: #cc0000;
        }
        
        .input-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .input-group input {
            padding: 8px 12px;
            background: #333;
            border: 1px solid #444;
            color: white;
            border-radius: 4px;
            font-size: 12px;
        }
        
        .status-bar {
            padding: 10px 15px;
            background: #222;
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
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <div style="background: #0066cc; padding: 15px 30px; color: white; display: flex; justify-content: space-between; align-items: center;">
        <div style="font-size: 18px; font-weight: bold;">🖥️ Remote Access Control</div>
        <div>
            <a href="dashboard.php" style="color: white; text-decoration: none; margin-right: 20px; font-weight: bold;">← Back to Dashboard</a>
            <a href="?logout=1" style="color: white; text-decoration: none; font-weight: bold;">Logout</a>
        </div>
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
                <h1>Remote Access Control</h1>
                <p id="agentInfo">Select an agent to begin remote access</p>
            </div>
            
            <!-- Content -->
            <div class="content">
                <div class="screen-area" id="screenArea">
                    <div class="screen-canvas" id="screenCanvas">
                        <div class="no-agent">Select an agent from the list</div>
                    </div>
                </div>
                
                <!-- Controls -->
                <div class="controls">
                    <button class="btn" onclick="takeScreenshot()">📷 Screenshot</button>
                    <button class="btn" onclick="sendCtrlAltDel()">⌨️ Ctrl+Alt+Del</button>
                    <button class="btn" onclick="lockScreen()">🔒 Lock Screen</button>
                    <button class="btn" onclick="restartPC()">🔄 Restart</button>
                    <button class="btn btn-danger" onclick="shutdownPC()">⏹️ Shutdown</button>
                    
                    <div class="input-group" style="margin-left: auto;">
                        <input type="text" id="commandInput" placeholder="Enter command..." style="width: 200px;">
                        <button class="btn" onclick="executeCommand()">Execute</button>
                    </div>
                </div>
                
                <!-- Status bar -->
                <div class="status-bar">
                    <span id="statusText">Ready. Select an agent to connect.</span>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let selectedAgent = '<?php echo $agent; ?>';
        let screenRefreshInterval = null;
        let isScreenActive = false;
        
        // DISABLED: Auto-refresh screenshot every 1.5 seconds
        // Use remote-terminal.php instead for shell commands
        function startLiveScreen() {
            if (screenRefreshInterval) clearInterval(screenRefreshInterval);
            
            isScreenActive = false;  // Disabled - use remote-terminal.php
            // Initial screenshot
            // refreshScreen();  // Disabled
            
            // Auto-refresh every 1.5 seconds - DISABLED
            // screenRefreshInterval = setInterval(refreshScreen, 1500);
            
            console.log('Live screen disabled. Use remote-terminal.php for commands.');
        }
        
        function stopLiveScreen() {
            isScreenActive = false;
            if (screenRefreshInterval) {
                clearInterval(screenRefreshInterval);
                screenRefreshInterval = null;
            }
        }
        
        function refreshScreen() {
            if (!selectedAgent || !isScreenActive) return;
            
            // Send screenshot command
            fetch(`/SIEM/api/remote-access.php?action=send_command&agent=${selectedAgent}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: 'screenshot'})
            }).catch(() => {});
            
            // Retrieve latest screenshot after 500ms
            setTimeout(() => {
                fetch(`/SIEM/api/remote-access.php?action=get_screen&agent=${selectedAgent}`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'success' && data.screenshot) {
                            const canvas = document.getElementById('screenCanvas');
                            canvas.innerHTML = `<img id="screenImg" src="data:image/png;base64,${data.screenshot}" style="max-width: 100%; max-height: 100%; object-fit: contain; cursor: crosshair;">`;
                            
                            // Add mouse click handler
                            document.getElementById('screenImg').addEventListener('click', handleMouseClick);
                            document.getElementById('screenImg').addEventListener('mousemove', handleMouseMove);
                        }
                    })
                    .catch(() => {});
            }, 500);
        }
        
        function handleMouseClick(e) {
            if (!selectedAgent) return;
            
            const img = e.target;
            const rect = img.getBoundingClientRect();
            const x = Math.round((e.clientX - rect.left) / rect.width * 1920);
            const y = Math.round((e.clientY - rect.top) / rect.height * 1080);
            
            // Send mouse click command
            fetch(`/SIEM/api/remote-access.php?action=send_command&agent=${selectedAgent}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: `mouse_click:${x}:${y}`})
            }).catch(() => {});
            
            document.getElementById('statusText').textContent = `Clicked at (${x}, ${y})`;
        }
        
        function handleMouseMove(e) {
            if (!selectedAgent) return;
            
            const img = e.target;
            const rect = img.getBoundingClientRect();
            const x = Math.round((e.clientX - rect.left) / rect.width * 1920);
            const y = Math.round((e.clientY - rect.top) / rect.height * 1080);
            
            // Send mouse move command (less frequently to avoid spam)
            if (Math.random() < 0.1) {
                fetch(`/SIEM/api/remote-access.php?action=send_command&agent=${selectedAgent}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: `mouse_move:${x}:${y}`})
                }).catch(() => {});
            }
        }
        
        // Load agent list
        function loadAgents() {
            fetch('/SIEM/api/remote-access.php?action=get_agents')
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('agentList');
                    list.innerHTML = '';
                    
                    if (data.agents.length === 0) {
                        list.innerHTML = '<li style="color: #666;">No agents connected</li>';
                        return;
                    }
                    
                    data.agents.forEach(agent => {
                        const li = document.createElement('li');
                        li.className = 'agent-item' + (agent.name === selectedAgent ? ' active' : '');
                        li.innerHTML = `
                            <div class="agent-name">${agent.name}</div>
                            <div class="agent-status">
                                <span class="status-${agent.status}">${agent.status}</span>
                                • ${agent.events} events
                            </div>
                        `;
                        li.onclick = () => selectAgent(agent.name);
                        list.appendChild(li);
                    });
                });
        }
        
        // Select agent
        function selectAgent(agentName) {
            selectedAgent = agentName;
            document.querySelectorAll('.agent-item').forEach(el => el.classList.remove('active'));
            event.target.closest('.agent-item').classList.add('active');
            
            fetch(`/SIEM/api/remote-access.php?action=get_agent_details&agent=${agentName}`)
                .then(r => r.json())
                .then(data => {
                    document.getElementById('agentInfo').textContent = 
                        `Connected to: ${data.agent} (${data.status}) • Last seen: ${data.last_seen}`;
                    document.getElementById('statusText').textContent = 
                        `Connected to ${data.agent}. Starting live screen...`;
                    
                    // Show screen area
                    document.getElementById('screenCanvas').innerHTML = 
                        '<div style="text-align: center; color: #666;"><p>📺 Live Remote Screen</p><p style="font-size: 11px; margin-top: 10px;">Loading...</p></div>';
                    
                    // Start live screen refresh
                    startLiveScreen();
                });
        }
        
        // Take screenshot
        function takeScreenshot() {
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }
            
            document.getElementById('statusText').textContent = 'Requesting screenshot...';
            
            // First send screenshot request command
            fetch(`/SIEM/api/remote-access.php?action=send_command&agent=${selectedAgent}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: 'screenshot'})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('statusText').textContent = 'Screenshot request sent, waiting for response...';
                
                // Wait 3 seconds then retrieve screenshot
                setTimeout(() => {
                    fetch(`/SIEM/api/remote-access.php?action=get_screen&agent=${selectedAgent}`)
                        .then(r => r.json())
                        .then(data => {
                            if (data.status === 'success' && data.screenshot) {
                                // Display screenshot
                                const canvas = document.getElementById('screenCanvas');
                                canvas.innerHTML = `<img src="data:image/png;base64,${data.screenshot}" style="max-width: 100%; max-height: 100%; object-fit: contain;">`;
                                document.getElementById('statusText').textContent = `Screenshot received at ${data.timestamp}`;
                            } else {
                                document.getElementById('statusText').textContent = 'Screenshot not available yet. Waiting for agent response...';
                            }
                        });
                }, 3000);
            });
        }
        
        // Send Ctrl+Alt+Del
        function sendCtrlAltDel() {
            if (!selectedAgent) return;
            sendCommand('ctrl+alt+del');
        }
        
        // Lock screen
        function lockScreen() {
            if (!selectedAgent) return;
            sendCommand('lock');
        }
        
        // Restart PC
        function restartPC() {
            if (!confirm('Restart ' + selectedAgent + '?')) return;
            sendCommand('restart');
        }
        
        // Shutdown PC
        function shutdownPC() {
            if (!confirm('Shutdown ' + selectedAgent + '?')) return;
            sendCommand('shutdown');
        }
        
        // Execute custom command
        function executeCommand() {
            const cmd = document.getElementById('commandInput').value;
            if (!cmd) return;
            sendCommand(cmd);
            document.getElementById('commandInput').value = '';
        }
        
        // Send command to agent
        function sendCommand(cmd) {
            fetch('/SIEM/api/remote-access.php?action=send_command&agent=' + selectedAgent, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: cmd})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('statusText').textContent = 'Command sent: ' + cmd;
            });
        }
        
        // Load agents on page load
        loadAgents();
        setInterval(loadAgents, 5000); // Refresh every 5 seconds
        
        // Select agent if provided in URL
        if (selectedAgent) {
            setTimeout(() => selectAgent(selectedAgent), 1000);
        }
    </script>
    
    <?php
    // Handle logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit;
    }
    
    $db->close();
    ?>
</body>
</html>
