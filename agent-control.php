<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JFS SIEM Agent Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --primary: #0066cc;
            --accent: #00d4ff;
            --success: #00cc66;
            --error: #ff3333;
            --bg: #0f1419;
            --surface: #1a1f26;
            --text: #ffffff;
            --text-dim: #b0b8c1;
        }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, var(--primary), #004499);
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        header h1 { font-size: 2em; margin-bottom: 10px; }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            border-bottom: 2px solid #3a4452;
        }
        .tab-btn {
            padding: 12px 20px;
            background: transparent;
            border: none;
            color: var(--text-dim);
            cursor: pointer;
            font-weight: 500;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        .tab-btn.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--surface);
            border: 1px solid #3a4452;
            border-radius: 8px;
            padding: 20px;
            transition: all 0.3s;
        }
        .card:hover {
            border-color: var(--accent);
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.1);
        }
        .card-title { font-size: 1.1em; font-weight: 600; margin-bottom: 10px; }
        .card-desc { font-size: 0.85em; color: var(--text-dim); margin-bottom: 15px; }
        input, select, textarea {
            width: 100%;
            padding: 10px;
            background: #252d36;
            border: 1px solid #3a4452;
            border-radius: 6px;
            color: var(--text);
            margin-bottom: 10px;
            font-family: inherit;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 10px rgba(0, 212, 255, 0.2);
        }
        button {
            padding: 10px 15px;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            width: 100%;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: #004499; }
        .btn-danger { background: var(--error); color: white; }
        .btn-danger:hover { background: #ff1111; }
        .btn-warning { background: #ff9900; color: white; }
        .btn-warning:hover { background: #ff8800; }
        .output {
            background: #252d36;
            border: 1px solid #3a4452;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
            font-family: monospace;
            font-size: 0.85em;
            max-height: 300px;
            overflow-y: auto;
            color: var(--accent);
            display: none;
        }
        .output.show { display: block; }
        label { display: block; font-size: 0.85em; color: var(--text-dim); margin-bottom: 5px; font-weight: 500; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>⚔️ JFS SIEM Agent Control Panel</h1>
            <p>Advanced threat simulation and security testing</p>
            <div style="margin-top: 20px; display: flex; gap: 15px; align-items: center;">
                <label style="color: rgba(255,255,255,0.9); margin: 0;">Select Agent:</label>
                <select id="agent-select" style="padding: 10px; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.3); border-radius: 6px; color: white; min-width: 250px; font-size: 0.95em;">
                    <option value="">-- Load Agents --</option>
                </select>
                <button onclick="loadAgents()" style="padding: 10px 20px; background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3); border-radius: 6px; color: white; cursor: pointer; font-weight: 600;">Refresh</button>
                <span id="agent-status" style="color: #b0b8c1; font-size: 0.9em;"></span>
            </div>
        </header>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('recon')">🔍 Reconnaissance</button>
            <button class="tab-btn" onclick="switchTab('creds')">🔑 Credentials</button>
            <button class="tab-btn" onclick="switchTab('persist')">📌 Persistence</button>
            <button class="tab-btn" onclick="switchTab('lateral')">🔀 Lateral</button>
            <button class="tab-btn" onclick="switchTab('evasion')">👻 Evasion</button>
            <button class="tab-btn" onclick="switchTab('exfil')">📤 Exfiltration</button>
            <button class="tab-btn" onclick="switchTab('malware')">🦠 Malware</button>
            <button class="tab-btn" onclick="switchTab('monitor')">📊 Monitor</button>
        </div>

        <!-- RECONNAISSANCE -->
        <div id="recon" class="tab-content active">
            <div class="grid">
                <div class="card">
                    <div class="card-title">System Info</div>
                    <div class="card-desc">Gather system information</div>
                    <select id="sysinfo-type">
                        <option value="sysinfo">System Info</option>
                        <option value="ipconfig">Network Config</option>
                        <option value="processes">Processes</option>
                        <option value="services">Services</option>
                    </select>
                    <button class="btn-primary" onclick="cmd('recon:sysinfo')">Execute</button>
                    <div class="output" id="out-recon-sysinfo"></div>
                </div>

                <div class="card">
                    <div class="card-title">Network Scan</div>
                    <div class="card-desc">Scan network for hosts</div>
                    <label>Target Network</label>
                    <input type="text" id="net-target" placeholder="192.168.1.0/24">
                    <button class="btn-primary" onclick="cmd('recon:network')">Scan</button>
                    <div class="output" id="out-recon-network"></div>
                </div>

                <div class="card">
                    <div class="card-title">File Enumeration</div>
                    <div class="card-desc">List files and directories</div>
                    <label>Path</label>
                    <input type="text" id="file-path" placeholder="C:\Users" value="C:\Users">
                    <button class="btn-primary" onclick="cmd('recon:files')">Enumerate</button>
                    <div class="output" id="out-recon-files"></div>
                </div>

                <div class="card">
                    <div class="card-title">Browser History</div>
                    <div class="card-desc">Extract browser history</div>
                    <button class="btn-primary" onclick="cmd('recon:browser')">Extract</button>
                    <div class="output" id="out-recon-browser"></div>
                </div>

                <div class="card">
                    <div class="card-title">USB Devices</div>
                    <div class="card-desc">List USB devices</div>
                    <button class="btn-primary" onclick="cmd('recon:usb')">List</button>
                    <div class="output" id="out-recon-usb"></div>
                </div>

                <div class="card">
                    <div class="card-title">Security Software</div>
                    <div class="card-desc">Detect AV/EDR/Firewall</div>
                    <button class="btn-warning" onclick="cmd('recon:security')">Detect</button>
                    <div class="output" id="out-recon-security"></div>
                </div>
            </div>
        </div>

        <!-- CREDENTIALS -->
        <div id="creds" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Browser Passwords</div>
                    <div class="card-desc">Extract saved passwords</div>
                    <button class="btn-danger" onclick="cmd('steal:browser')">Extract</button>
                    <div class="output" id="out-steal-browser"></div>
                </div>

                <div class="card">
                    <div class="card-title">SSH Keys</div>
                    <div class="card-desc">Extract SSH private keys</div>
                    <button class="btn-danger" onclick="cmd('steal:ssh')">Extract</button>
                    <div class="output" id="out-steal-ssh"></div>
                </div>

                <div class="card">
                    <div class="card-title">NTLM Hashes</div>
                    <div class="card-desc">Dump NTLM hashes</div>
                    <button class="btn-danger" onclick="cmd('steal:ntlm')">Dump</button>
                    <div class="output" id="out-steal-ntlm"></div>
                </div>

                <div class="card">
                    <div class="card-title">Kerberos Tickets</div>
                    <div class="card-desc">Extract Kerberos tickets</div>
                    <button class="btn-danger" onclick="cmd('steal:kerberos')">Extract</button>
                    <div class="output" id="out-steal-kerberos"></div>
                </div>

                <div class="card">
                    <div class="card-title">API Keys</div>
                    <div class="card-desc">Extract API keys from environment</div>
                    <button class="btn-danger" onclick="cmd('steal:api')">Extract</button>
                    <div class="output" id="out-steal-api"></div>
                </div>

                <div class="card">
                    <div class="card-title">Stored Credentials</div>
                    <div class="card-desc">Extract Windows credentials</div>
                    <button class="btn-danger" onclick="cmd('steal:stored')">Extract</button>
                    <div class="output" id="out-steal-stored"></div>
                </div>
            </div>
        </div>

        <!-- PERSISTENCE -->
        <div id="persist" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Registry Run Key</div>
                    <div class="card-desc">Add registry persistence</div>
                    <button class="btn-warning" onclick="cmd('persist:registry')">Install</button>
                    <div class="output" id="out-persist-registry"></div>
                </div>

                <div class="card">
                    <div class="card-title">Startup Folder</div>
                    <div class="card-desc">Add startup shortcut</div>
                    <button class="btn-warning" onclick="cmd('persist:startup')">Install</button>
                    <div class="output" id="out-persist-startup"></div>
                </div>

                <div class="card">
                    <div class="card-title">Scheduled Task</div>
                    <div class="card-desc">Create scheduled task</div>
                    <label>Task Name</label>
                    <input type="text" id="task-name" placeholder="SystemUpdate" value="SystemUpdate">
                    <button class="btn-warning" onclick="cmd('persist:task')">Create</button>
                    <div class="output" id="out-persist-task"></div>
                </div>

                <div class="card">
                    <div class="card-title">WMI Event</div>
                    <div class="card-desc">WMI event subscription</div>
                    <button class="btn-warning" onclick="cmd('persist:wmi')">Install</button>
                    <div class="output" id="out-persist-wmi"></div>
                </div>

                <div class="card">
                    <div class="card-title">COM Hijacking</div>
                    <div class="card-desc">Hijack COM objects</div>
                    <button class="btn-warning" onclick="cmd('persist:com')">Install</button>
                    <div class="output" id="out-persist-com"></div>
                </div>

                <div class="card">
                    <div class="card-title">IFEO Persistence</div>
                    <div class="card-desc">Image File Execution Options</div>
                    <label>Target Process</label>
                    <input type="text" id="ifeo-target" placeholder="notepad.exe" value="notepad.exe">
                    <button class="btn-warning" onclick="cmd('persist:ifeo')">Install</button>
                    <div class="output" id="out-persist-ifeo"></div>
                </div>
            </div>
        </div>

        <!-- LATERAL MOVEMENT -->
        <div id="lateral" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Pass-the-Hash</div>
                    <div class="card-desc">PTH lateral movement</div>
                    <label>Target Host</label>
                    <input type="text" id="pth-host" placeholder="192.168.1.100">
                    <label>Username</label>
                    <input type="text" id="pth-user" placeholder="Administrator">
                    <label>NTLM Hash</label>
                    <input type="text" id="pth-hash" placeholder="hash">
                    <button class="btn-danger" onclick="cmd('lateral:pth')">Execute</button>
                    <div class="output" id="out-lateral-pth"></div>
                </div>

                <div class="card">
                    <div class="card-title">Kerberoasting</div>
                    <div class="card-desc">Extract service tickets</div>
                    <label>Domain</label>
                    <input type="text" id="kerb-domain" placeholder="corp.local">
                    <button class="btn-danger" onclick="cmd('lateral:kerberoast')">Kerberoast</button>
                    <div class="output" id="out-lateral-kerberoast"></div>
                </div>

                <div class="card">
                    <div class="card-title">Golden Ticket</div>
                    <div class="card-desc">Forged Kerberos TGT</div>
                    <label>Domain</label>
                    <input type="text" id="gold-domain" placeholder="corp.local">
                    <button class="btn-danger" onclick="cmd('lateral:golden')">Create</button>
                    <div class="output" id="out-lateral-golden"></div>
                </div>

                <div class="card">
                    <div class="card-title">Silver Ticket</div>
                    <div class="card-desc">Forged Kerberos TGS</div>
                    <label>Service</label>
                    <input type="text" id="silver-svc" placeholder="CIFS" value="CIFS">
                    <label>Host</label>
                    <input type="text" id="silver-host" placeholder="fileserver.local">
                    <button class="btn-danger" onclick="cmd('lateral:silver')">Create</button>
                    <div class="output" id="out-lateral-silver"></div>
                </div>

                <div class="card">
                    <div class="card-title">Overpass-the-Hash</div>
                    <div class="card-desc">NTLM to Kerberos</div>
                    <label>Username</label>
                    <input type="text" id="over-user" placeholder="Administrator">
                    <button class="btn-danger" onclick="cmd('lateral:overpass')">Execute</button>
                    <div class="output" id="out-lateral-overpass"></div>
                </div>

                <div class="card">
                    <div class="card-title">WMI Lateral</div>
                    <div class="card-desc">Execute via WMI</div>
                    <label>Target</label>
                    <input type="text" id="wmi-target" placeholder="192.168.1.100">
                    <label>Command</label>
                    <input type="text" id="wmi-cmd" placeholder="whoami">
                    <button class="btn-danger" onclick="cmd('lateral:wmi')">Execute</button>
                    <div class="output" id="out-lateral-wmi"></div>
                </div>
            </div>
        </div>

        <!-- EVASION -->
        <div id="evasion" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">VM Detection</div>
                    <div class="card-desc">Detect virtual machine</div>
                    <button class="btn-warning" onclick="cmd('anti:vm')">Check</button>
                    <div class="output" id="out-anti-vm"></div>
                </div>

                <div class="card">
                    <div class="card-title">Sandbox Detection</div>
                    <div class="card-desc">Detect sandbox</div>
                    <button class="btn-warning" onclick="cmd('anti:sandbox')">Check</button>
                    <div class="output" id="out-anti-sandbox"></div>
                </div>

                <div class="card">
                    <div class="card-title">Debugger Detection</div>
                    <div class="card-desc">Detect debugger</div>
                    <button class="btn-warning" onclick="cmd('anti:debugger')">Check</button>
                    <div class="output" id="out-anti-debugger"></div>
                </div>

                <div class="card">
                    <div class="card-title">AMSI Bypass</div>
                    <div class="card-desc">Bypass AMSI</div>
                    <button class="btn-danger" onclick="cmd('anti:amsi')">Bypass</button>
                    <div class="output" id="out-anti-amsi"></div>
                </div>

                <div class="card">
                    <div class="card-title">ETW Bypass</div>
                    <div class="card-desc">Bypass ETW</div>
                    <button class="btn-danger" onclick="cmd('anti:etw')">Bypass</button>
                    <div class="output" id="out-anti-etw"></div>
                </div>

                <div class="card">
                    <div class="card-title">Defender Exclusion</div>
                    <div class="card-desc">Add exclusion</div>
                    <label>Path</label>
                    <input type="text" id="def-path" placeholder="C:\Windows\Temp">
                    <button class="btn-danger" onclick="cmd('anti:defender')">Add</button>
                    <div class="output" id="out-anti-defender"></div>
                </div>
            </div>
        </div>

        <!-- EXFILTRATION -->
        <div id="exfil" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">DNS Exfiltration</div>
                    <div class="card-desc">Exfil via DNS</div>
                    <label>Data</label>
                    <textarea id="dns-data" placeholder="Data" rows="3"></textarea>
                    <button class="btn-danger" onclick="cmd('exfil:dns')">Send</button>
                    <div class="output" id="out-exfil-dns"></div>
                </div>

                <div class="card">
                    <div class="card-title">HTTP Exfiltration</div>
                    <div class="card-desc">Exfil via HTTP</div>
                    <label>URL</label>
                    <input type="text" id="http-url" placeholder="http://attacker.com">
                    <button class="btn-danger" onclick="cmd('exfil:http')">Send</button>
                    <div class="output" id="out-exfil-http"></div>
                </div>

                <div class="card">
                    <div class="card-title">Email Exfiltration</div>
                    <div class="card-desc">Exfil via email</div>
                    <label>Recipient</label>
                    <input type="text" id="email-to" placeholder="attacker@example.com">
                    <button class="btn-danger" onclick="cmd('exfil:email')">Send</button>
                    <div class="output" id="out-exfil-email"></div>
                </div>

                <div class="card">
                    <div class="card-title">Cloud Exfiltration</div>
                    <div class="card-desc">Exfil to cloud</div>
                    <select id="cloud-svc">
                        <option value="onedrive">OneDrive</option>
                        <option value="dropbox">Dropbox</option>
                        <option value="gdrive">Google Drive</option>
                    </select>
                    <button class="btn-danger" onclick="cmd('exfil:cloud')">Send</button>
                    <div class="output" id="out-exfil-cloud"></div>
                </div>

                <div class="card">
                    <div class="card-title">ICMP Tunneling</div>
                    <div class="card-desc">Tunnel via ICMP</div>
                    <label>Target IP</label>
                    <input type="text" id="icmp-ip" placeholder="192.168.1.1">
                    <button class="btn-danger" onclick="cmd('exfil:icmp')">Tunnel</button>
                    <div class="output" id="out-exfil-icmp"></div>
                </div>

                <div class="card">
                    <div class="card-title">SMB Exfiltration</div>
                    <div class="card-desc">Exfil via SMB</div>
                    <label>Share</label>
                    <input type="text" id="smb-share" placeholder="\\server\share">
                    <button class="btn-danger" onclick="cmd('exfil:smb')">Send</button>
                    <div class="output" id="out-exfil-smb"></div>
                </div>
            </div>
        </div>

        <!-- MALWARE -->
        <div id="malware" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Ransomware</div>
                    <div class="card-desc">Simulate ransomware</div>
                    <label>Directory</label>
                    <input type="text" id="ransom-dir" placeholder="C:\Users\Public\Documents">
                    <button class="btn-danger" onclick="cmd('malware:ransomware')">Simulate</button>
                    <div class="output" id="out-malware-ransomware"></div>
                </div>

                <div class="card">
                    <div class="card-title">Worm</div>
                    <div class="card-desc">Simulate worm</div>
                    <label>Share</label>
                    <input type="text" id="worm-share" placeholder="\\server\share">
                    <button class="btn-danger" onclick="cmd('malware:worm')">Propagate</button>
                    <div class="output" id="out-malware-worm"></div>
                </div>

                <div class="card">
                    <div class="card-title">Botnet</div>
                    <div class="card-desc">Setup botnet</div>
                    <label>C2 Server</label>
                    <input type="text" id="botnet-c2" placeholder="attacker.com:8080">
                    <button class="btn-danger" onclick="cmd('malware:botnet')">Setup</button>
                    <div class="output" id="out-malware-botnet"></div>
                </div>

                <div class="card">
                    <div class="card-title">DDoS</div>
                    <div class="card-desc">Launch DDoS</div>
                    <label>Target</label>
                    <input type="text" id="ddos-target" placeholder="http://target.com">
                    <button class="btn-danger" onclick="cmd('malware:ddos')">Attack</button>
                    <div class="output" id="out-malware-ddos"></div>
                </div>

                <div class="card">
                    <div class="card-title">Cryptominer</div>
                    <div class="card-desc">Start miner</div>
                    <label>Pool</label>
                    <input type="text" id="miner-pool" placeholder="pool.monero.com:3333">
                    <button class="btn-danger" onclick="cmd('malware:miner')">Start</button>
                    <div class="output" id="out-malware-miner"></div>
                </div>

                <div class="card">
                    <div class="card-title">Reverse Shell</div>
                    <div class="card-desc">Reverse shell</div>
                    <label>IP:Port</label>
                    <input type="text" id="shell-addr" placeholder="192.168.1.100:4444">
                    <button class="btn-danger" onclick="cmd('malware:shell')">Connect</button>
                    <div class="output" id="out-malware-shell"></div>
                </div>
            </div>
        </div>

        <!-- MONITORING -->
        <div id="monitor" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">File Monitoring</div>
                    <div class="card-desc">Monitor file changes</div>
                    <button class="btn-primary" onclick="cmd('monitor:file')">Start</button>
                    <div class="output" id="out-monitor-file"></div>
                </div>

                <div class="card">
                    <div class="card-title">Registry Monitoring</div>
                    <div class="card-desc">Monitor registry</div>
                    <button class="btn-primary" onclick="cmd('monitor:registry')">Start</button>
                    <div class="output" id="out-monitor-registry"></div>
                </div>

                <div class="card">
                    <div class="card-title">Process Monitoring</div>
                    <div class="card-desc">Monitor processes</div>
                    <button class="btn-primary" onclick="cmd('monitor:process')">Start</button>
                    <div class="output" id="out-monitor-process"></div>
                </div>

                <div class="card">
                    <div class="card-title">Network Monitoring</div>
                    <div class="card-desc">Monitor connections</div>
                    <button class="btn-primary" onclick="cmd('monitor:network')">Start</button>
                    <div class="output" id="out-monitor-network"></div>
                </div>

                <div class="card">
                    <div class="card-title">Event Log Monitoring</div>
                    <div class="card-desc">Monitor event logs</div>
                    <button class="btn-primary" onclick="cmd('monitor:eventlog')">Start</button>
                    <div class="output" id="out-monitor-eventlog"></div>
                </div>

                <div class="card">
                    <div class="card-title">Screenshot</div>
                    <div class="card-desc">Capture screenshot</div>
                    <button class="btn-primary" onclick="cmd('monitor:screenshot')">Capture</button>
                    <div class="output" id="out-monitor-screenshot"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let selectedAgent = null;

        // Load agents on page load
        window.addEventListener('DOMContentLoaded', loadAgents);

        function loadAgents() {
            const select = document.getElementById('agent-select');
            const status = document.getElementById('agent-status');
            
            status.textContent = '⏳ Loading agents...';
            
            // Add cache buster to force fresh data
            fetch('api/get-agents.php?t=' + Date.now())
                .then(r => r.json())
                .then(data => {
                    select.innerHTML = '<option value="">-- Select Agent --</option>';
                    
                    if (data.agents && data.agents.length > 0) {
                        data.agents.forEach(agent => {
                            const option = document.createElement('option');
                            option.value = agent.id;
                            option.textContent = `${agent.name} (${agent.ip}) - ${agent.status}`;
                            select.appendChild(option);
                        });
                        status.textContent = `✓ ${data.agents.length} agent(s) found`;
                    } else {
                        status.textContent = '⚠ No agents in database. Visit /SIEM/api/test-register-agents.php to add test agents';
                    }
                })
                .catch(e => {
                    status.textContent = '❌ Error loading agents: ' + e.message;
                    console.error(e);
                });
            
            select.addEventListener('change', (e) => {
                selectedAgent = e.target.value;
                if (selectedAgent) {
                    status.textContent = `✓ Agent selected: ${e.target.options[e.target.selectedIndex].text}`;
                }
            });
        }

        function switchTab(name) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(name).classList.add('active');
            event.target.classList.add('active');
        }

        function cmd(command) {
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }

            const parts = command.split(':');
            const category = parts[0];
            const action = parts[1];
            const outputId = `out-${category}-${action}`;
            const output = document.getElementById(outputId);
            
            if (!output) return;
            
            output.classList.add('show');
            output.textContent = '⏳ Executing on ' + document.getElementById('agent-select').options[document.getElementById('agent-select').selectedIndex].text + '...';
            
            fetch('api/agent-command.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    command: command,
                    agent_id: selectedAgent
                })
            })
            .then(r => r.json())
            .then(d => {
                output.textContent = d.output || d.error || 'No output';
            })
            .catch(e => {
                output.textContent = '❌ Error: ' + e.message;
            });
        }
    </script>
</body>
</html>
