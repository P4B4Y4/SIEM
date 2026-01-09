<?php
session_start();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$agent = $_GET['agent'] ?? '';
$tab = $_GET['tab'] ?? 'processes';
$tab = in_array($tab, ['processes', 'services', 'tasks'], true) ? $tab : 'processes';
?>
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Task Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a0e27; color: #e6edf3; }
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

        .agent-list { list-style: none; }

        .agent-item {
            padding: 10px;
            margin-bottom: 8px;
            background: #1a1f26;
            border-radius: 4px;
            cursor: pointer;
            border-left: 3px solid #333;
            transition: all 0.3s;
        }

        .agent-item:hover { background: #2a2a2a; border-left-color: #0066cc; }

        .agent-item.active { background: #0066cc; border-left-color: #00d4ff; }

        .agent-name { font-weight: 700; font-family: 'Courier New', monospace; color: #00ff00; }
        .agent-meta { font-size: 12px; margin-top: 4px; opacity: 0.9; color: #00ff00; font-family: 'Courier New', monospace; }

        .main { flex: 1; display: flex; flex-direction: column; }

        .topbar {
            background: #0066cc;
            padding: 15px 30px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .topbar a { color: white; text-decoration: none; font-weight: bold; }

        .header {
            background: #0f1419;
            padding: 16px 20px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }

        .header-left h1 { font-size: 20px; color: #fff; }
        .header-left p { font-size: 12px; color: #b6c2cf; margin-top: 4px; }

        .tabs { display: flex; gap: 8px; }
        .tab {
            padding: 8px 12px;
            border: 1px solid #2b2f36;
            background: #1a1f26;
            color: #e6edf3;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }
        .tab.active { background: #0066cc; border-color: #0066cc; }

        .content { flex: 1; overflow: auto; padding: 20px; }

        .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
        .toolbar input {
            padding: 10px;
            background: #1a1f26;
            border: 1px solid #333;
            color: #e6edf3;
            border-radius: 6px;
            min-width: 280px;
        }

        .btn {
            padding: 10px 14px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 700;
        }
        .btn:hover { background: #004499; }
        .btn.secondary { background: #333; }
        .btn.secondary:hover { background: #444; }
        .btn.danger { background: #c0392b; }
        .btn.danger:hover { background: #a93226; }

        .card {
            background: #0f1419;
            border: 1px solid #333;
            border-radius: 10px;
            overflow: hidden;
        }

        table { width: 100%; border-collapse: collapse; }
        thead { background: #1a1f26; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #222; font-size: 13px; }
        th { color: #9fb3c8; font-weight: 700; text-transform: uppercase; font-size: 11px; }
        tr:hover td { background: #101827; }

        .badge { padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; display: inline-block; }
        .badge.ok { background: rgba(46, 204, 113, 0.15); color: #2ecc71; border: 1px solid rgba(46, 204, 113, 0.25); }
        .badge.warn { background: rgba(241, 196, 15, 0.15); color: #f1c40f; border: 1px solid rgba(241, 196, 15, 0.25); }
        .badge.bad { background: rgba(231, 76, 60, 0.15); color: #e74c3c; border: 1px solid rgba(231, 76, 60, 0.25); }

        .status { color: #b6c2cf; font-size: 12px; margin-left: 8px; }

        .modal-backdrop {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.65);
            z-index: 999;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .modal {
            width: 100%;
            max-width: 650px;
            background: #0f1419;
            border: 1px solid #333;
            border-radius: 12px;
            padding: 16px;
        }

        .modal h2 { font-size: 16px; margin-bottom: 12px; }
        .modal .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .modal label { font-size: 12px; color: #9fb3c8; font-weight: 700; display: block; margin-bottom: 6px; }
        .modal input { width: 100%; padding: 10px; background: #1a1f26; border: 1px solid #333; color: #e6edf3; border-radius: 6px; }
        .modal .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }

        @media (max-width: 900px) {
            .container { flex-direction: column; }
            .sidebar { width: 100%; height: auto; }
        }
    </style>
</head>
<body>
    <div class="topbar">
        <div style="font-size: 18px; font-weight: bold;">Task Manager</div>
        <div style="display:flex; gap: 18px;">
            <a href="dashboard.php">← Back to Dashboard</a>
            <a href="?logout=1">Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="sidebar">
            <h3>Connected Agents</h3>
            <ul class="agent-list" id="agentList">
                <li style="color: #666; text-align: center; padding: 20px;">Loading...</li>
            </ul>
        </div>

        <div class="main">
            <div class="header">
                <div class="header-left">
                    <h1>Task Manager</h1>
                    <p id="agentInfo">Select an agent to view Processes / Services / Scheduled Tasks</p>
                </div>
                <div class="tabs">
                    <button class="tab" id="tab-processes" onclick="switchTab('processes')">Processes</button>
                    <button class="tab" id="tab-services" onclick="switchTab('services')">Services</button>
                    <button class="tab" id="tab-tasks" onclick="switchTab('tasks')">Scheduled Tasks</button>
                </div>
            </div>

            <div class="content">
                <div class="toolbar">
                    <input type="text" id="searchBox" placeholder="Search..." oninput="renderCurrent()" />
                    <button class="btn" onclick="refreshCurrent()">Refresh</button>
                    <button class="btn secondary" onclick="forceCleanupAgent()">Force Cleanup (Agent)</button>
                    <button class="btn secondary" onclick="forceCleanupAll()">Force Cleanup (All)</button>
                    <button class="btn secondary" id="btnStartProcess" onclick="openStartProcessModal()" style="display:none;">Start New Process</button>
                    <span class="status" id="statusText">Ready. Select an agent.</span>
                </div>

                <div class="card" id="systemSummaryCard" style="margin-bottom:12px; display:none;">
                    <div style="padding:12px 14px; border-bottom:1px solid #222; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                        <div style="font-weight:800; color:#9fb3c8; text-transform:uppercase; font-size:11px;">System Usage</div>
                        <div id="summaryCapturedAt" style="font-size:11px; color:#b6c2cf;"></div>
                    </div>
                    <div style="display:flex; gap:12px; padding:12px 14px; flex-wrap:wrap;">
                        <div style="min-width:160px; flex:1;">
                            <div style="font-size:11px; color:#9fb3c8; font-weight:700;">CPU</div>
                            <div id="summaryCpu" style="font-size:18px; font-weight:900;"></div>
                        </div>
                        <div style="min-width:160px; flex:1;">
                            <div style="font-size:11px; color:#9fb3c8; font-weight:700;">Memory</div>
                            <div id="summaryMem" style="font-size:18px; font-weight:900;"></div>
                        </div>
                        <div style="min-width:260px; flex:2;">
                            <div style="font-size:11px; color:#9fb3c8; font-weight:700;">Disks</div>
                            <div id="summaryDisks" style="font-size:12px; color:#e6edf3; margin-top:6px;"></div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <table>
                        <thead>
                            <tr id="tableHeadRow"></tr>
                        </thead>
                        <tbody id="tableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="modal-backdrop" id="startProcModal">
        <div class="modal">
            <h2>Start New Process</h2>
            <div class="row">
                <div>
                    <label>File Path</label>
                    <input id="spPath" placeholder="C:\\Windows\\System32\\notepad.exe" />
                </div>
                <div>
                    <label>Arguments (optional)</label>
                    <input id="spArgs" placeholder="" />
                </div>
                <div>
                    <label>Working Directory (optional)</label>
                    <input id="spWd" placeholder="C:\\Temp" />
                </div>
                <div>
                    <label>&nbsp;</label>
                    <div style="font-size:12px;color:#9fb3c8;">Restart is enabled only when ExecutablePath is available.</div>
                </div>
            </div>
            <div class="actions">
                <button class="btn secondary" onclick="closeStartProcessModal()">Cancel</button>
                <button class="btn" onclick="startProcessNow()">Start</button>
            </div>
        </div>
    </div>

    <script>
        let selectedAgent = '<?php echo htmlspecialchars($agent, ENT_QUOTES); ?>';
        let currentTab = '<?php echo htmlspecialchars($tab, ENT_QUOTES); ?>';

        const BASE_PATH = <?php echo json_encode(rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'])), '/\\')); ?>;

        let inFlight = false;

        let cache = {
            processes: [],
            services: [],
            tasks: []
        };

        let systemSummary = null;

        let procMeta = {
            cpuCount: null,
            capturedAt: null,
            clientCapturedAt: null
        };

        let procPrev = {
            ts: null,
            cpuCount: null,
            byPid: {}
        };

        let sortState = {
            tab: null,
            key: null,
            dir: 'desc'
        };

        window.addEventListener('load', () => {
            loadAgents();
            switchTab(currentTab);
            if (selectedAgent) {
                selectAgent(selectedAgent);
            }
        });

        function setActiveTabUI() {
            ['processes','services','tasks'].forEach(t => {
                document.getElementById('tab-' + t).classList.toggle('active', t === currentTab);
            });
            document.getElementById('btnStartProcess').style.display = (currentTab === 'processes') ? 'inline-block' : 'none';
        }

        function switchTab(tab) {
            currentTab = tab;
            setActiveTabUI();
            renderCurrent();

            const url = new URL(window.location.href);
            url.searchParams.set('tab', tab);
            if (selectedAgent) url.searchParams.set('agent', selectedAgent);
            window.history.replaceState({}, '', url);
        }

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

                            const displayName = agent.agent_id ? agent.agent_id : agent.name;
                            const secondary = agent.agent_id ? agent.name : (agent.ip ? agent.ip : '');

                            li.innerHTML = `
                                <div class="agent-name">${escapeHtml(displayName)}</div>
                                <div class="agent-meta">${escapeHtml(agent.status)} • ${escapeHtml(agent.events)} events</div>
                                ${secondary ? `<div class=\"agent-meta\">${escapeHtml(secondary)}</div>` : ''}
                            `;
                            li.onclick = (e) => selectAgent(agent.name, e);
                            list.appendChild(li);
                        });
                    } else {
                        list.innerHTML = '<li style="color: #666; text-align: center; padding: 20px;">No agents connected</li>';
                    }
                });
        }

        function selectAgent(agent, ev) {
            selectedAgent = agent;
            document.querySelectorAll('.agent-item').forEach(el => el.classList.remove('active'));
            if (ev && ev.target) {
                ev.target.closest('.agent-item')?.classList.add('active');
            }

            document.getElementById('agentInfo').textContent = `Selected agent: ${agent}`;
            document.getElementById('statusText').textContent = `Connected to ${agent}.`;

            const url = new URL(window.location.href);
            url.searchParams.set('agent', selectedAgent);
            url.searchParams.set('tab', currentTab);
            window.history.replaceState({}, '', url);

            document.getElementById('statusText').textContent = 'Selected. Click Refresh to load data.';
        }

        function refreshCurrent() {
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }

            if (inFlight) {
                document.getElementById('statusText').textContent = 'Please wait... request in progress.';
                return;
            }

            inFlight = true;

            const tabAtRequest = currentTab;

            document.getElementById('statusText').textContent = 'Refreshing...';
            if (tabAtRequest === 'processes') {
                Promise.all([
                    queueAction('list_processes', {}, tabAtRequest).then(items => { cache.processes = items; }),
                    queueAction('system_summary', {}, tabAtRequest).then(sum => { systemSummary = (sum && sum[0]) ? sum[0] : sum; renderSummary(); })
                ]).then(() => {
                    renderCurrent();
                }).finally(() => { inFlight = false; });
            } else if (tabAtRequest === 'services') {
                queueAction('list_services', {}, tabAtRequest).then(items => {
                    cache.services = items;
                    renderCurrent();
                }).finally(() => { inFlight = false; });
            } else {
                queueAction('list_tasks', {}, tabAtRequest).then(items => {
                    cache.tasks = items;
                    renderCurrent();
                }).finally(() => { inFlight = false; });
            }
        }

        function renderSummary() {
            const card = document.getElementById('systemSummaryCard');
            if (!card) return;
            if (!selectedAgent || !systemSummary || (systemSummary && systemSummary.error)) {
                card.style.display = 'none';
                return;
            }

            card.style.display = 'block';

            const cpu = systemSummary.CpuPct;
            const mem = systemSummary.MemPct;
            const drives = systemSummary.Drives;
            const capturedAt = systemSummary.CapturedAt;

            const cpuClass = usageClass(cpu, { warn: 60, bad: 85 });
            const memClass = usageClass(mem, { warn: 70, bad: 90 });

            document.getElementById('summaryCpu').innerHTML = `<span class="badge ${cpuClass}">${escapeHtml(fmtPct(cpu, 1) || '—')}</span>`;
            document.getElementById('summaryMem').innerHTML = `<span class="badge ${memClass}">${escapeHtml(fmtPct(mem, 1) || '—')}</span>`;
            document.getElementById('summaryCapturedAt').textContent = capturedAt ? ('Captured: ' + capturedAt) : '';

            const diskEl = document.getElementById('summaryDisks');
            if (!diskEl) return;
            const arr = Array.isArray(drives) ? drives : [];
            if (arr.length === 0) {
                diskEl.textContent = '—';
                return;
            }

            diskEl.innerHTML = arr.map(d => {
                const name = d.Name || '';
                const used = d.UsedPct;
                const size = d.SizeGB;
                const free = d.FreeGB;
                const cls = usageClass(used, { warn: 80, bad: 92 });
                const detail = `${escapeHtml(String(name))}: ${escapeHtml(fmtPct(used, 1) || '—')} used (${escapeHtml(fmtNum(size, 1) || '')} GB total, ${escapeHtml(fmtNum(free, 1) || '')} GB free)`;
                return `<div style="margin-top:4px;"><span class="badge ${cls}">${escapeHtml(String(name))}</span> <span style="margin-left:6px;">${detail}</span></div>`;
            }).join('');
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
                    if (data.status !== 'ok') throw new Error(data.error || 'Cleanup failed');
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
                    if (data.status !== 'ok') throw new Error(data.error || 'Cleanup failed');
                    document.getElementById('statusText').textContent = `Cleanup complete (all). Cleared: ${data.affected}`;
                })
                .catch(err => {
                    document.getElementById('statusText').textContent = `Cleanup error: ${err.message}`;
                });
        }

        function queueAction(action, payload, tabContext) {
            document.getElementById('statusText').textContent = `Queuing: ${action} (${tabContext || ''})...`;
            return fetch(`${BASE_PATH}/api/task-manager.php?action=${encodeURIComponent(action)}&agent=${encodeURIComponent(selectedAgent)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {})
            })
            .then(r => r.json())
            .then(data => {
                if (data.status !== 'ok') {
                    throw new Error(data.error || 'Failed');
                }
                document.getElementById('statusText').textContent = `Queued: ${action} (${tabContext || ''}) cmd#${data.command_id}. Waiting...`;
                return pollCommand(data.command_id, tabContext, action);
            })
            .catch(err => {
                document.getElementById('statusText').textContent = `Error: ${err.message}`;
                throw err;
            });
        }

        function pollCommand(commandId, tabContext, actionName) {
            let pollCount = 0;
            const maxPolls = 90;

            return new Promise((resolve, reject) => {
                const interval = setInterval(() => {
                    pollCount++;
                    fetch(`${BASE_PATH}/api/remote-access.php?action=get_command_result&command_id=${encodeURIComponent(commandId)}`)
                        .then(r => r.json())
                        .then(data => {
                            if (data.status === 'completed' || data.status === 'success' || data.status === 'failed' || data.status === 'error') {
                                clearInterval(interval);

                                if (data.error && (data.status === 'failed' || data.status === 'error')) {
                                    reject(new Error(data.error));
                                    return;
                                }

                                const out = (data.output || '').trim();

                                function tryParseFirstJsonPayload(text) {
                                    const s = (text || '').trim();
                                    if (!s) return null;

                                    // Fast path
                                    try { return JSON.parse(s); } catch (e) {}

                                    // If output contains CLIXML or other noise, try to locate a JSON object/array.
                                    const firstObj = s.indexOf('{');
                                    const firstArr = s.indexOf('[');
                                    const starts = [firstObj, firstArr].filter(i => i !== -1);
                                    if (starts.length === 0) return null;

                                    const start = Math.min(...starts);
                                    const tail = s.substring(start);

                                    // Incremental parse: expand window until it becomes valid JSON.
                                    // Caps to avoid huge loops.
                                    const maxLen = Math.min(tail.length, 200000);
                                    for (let end = 2; end <= maxLen; end++) {
                                        const chunk = tail.substring(0, end);
                                        try {
                                            return JSON.parse(chunk);
                                        } catch (e) {
                                            // keep expanding
                                        }
                                    }
                                    return null;
                                }

                                const parsed = tryParseFirstJsonPayload(out);
                                if (parsed == null) {
                                    const snippet = (out || '').slice(0, 400);
                                    reject(new Error('Agent did not return valid JSON. Snippet: ' + snippet));
                                    return;
                                }

                                try {
                                    const kind = Array.isArray(parsed) ? 'array' : (parsed === null ? 'null' : typeof parsed);
                                    const len = Array.isArray(parsed) ? parsed.length : (parsed && typeof parsed === 'object' && Array.isArray(parsed.items) ? parsed.items.length : '');
                                    document.getElementById('statusText').textContent = `Received ${actionName || ''} (${tabContext || ''}): ${kind}${len !== '' ? ' len=' + len : ''}`;
                                } catch (e) {}

                                // Agent-side scripts return either an array or an error object like {"error":"..."}
                                if (parsed && !Array.isArray(parsed) && typeof parsed === 'object' && parsed.error) {
                                    reject(new Error(String(parsed.error)));
                                    return;
                                }

                                // Processes list now returns { meta: {...}, items: [...] }
                                if (tabContext === 'processes' && parsed && !Array.isArray(parsed) && typeof parsed === 'object' && Array.isArray(parsed.items)) {
                                    try {
                                        procMeta.cpuCount = (parsed.meta && parsed.meta.CpuCount != null) ? Number(parsed.meta.CpuCount) : null;
                                        procMeta.capturedAt = (parsed.meta && parsed.meta.CapturedAt) ? String(parsed.meta.CapturedAt) : null;
                                    } catch (e) {
                                        procMeta.cpuCount = null;
                                        procMeta.capturedAt = null;
                                    }

                                    // Use client-side time for delta calculations (more stable than remote timestamps)
                                    procMeta.clientCapturedAt = Date.now();

                                    resolve(parsed.items);
                                    return;
                                }

                                document.getElementById('statusText').textContent = 'Updated.';
                                resolve(Array.isArray(parsed) ? parsed : (parsed ? [parsed] : []));
                            } else if (pollCount >= maxPolls) {
                                clearInterval(interval);
                                reject(new Error('Timeout waiting for agent response'));
                            }
                        })
                        .catch(err => {
                            if (pollCount >= maxPolls) {
                                clearInterval(interval);
                                reject(err);
                            }
                        });
                }, 1000);
            });
        }

        function renderCurrent() {
            setActiveTabUI();
            const q = (document.getElementById('searchBox').value || '').toLowerCase();

            let items = [];
            if (currentTab === 'processes') items = cache.processes;
            if (currentTab === 'services') items = cache.services;
            if (currentTab === 'tasks') items = cache.tasks;

            const filtered = (items || []).filter(x => {
                const hay = JSON.stringify(x || {}).toLowerCase();
                return q ? hay.includes(q) : true;
            });

            renderTable(applySort(filtered));
        }

        function applySort(items) {
            if (!sortState.key || sortState.tab !== currentTab) return items;
            const dirMul = sortState.dir === 'asc' ? 1 : -1;
            const key = sortState.key;

            const copy = (items || []).slice();
            copy.sort((a, b) => {
                const av = (a || {})[key];
                const bv = (b || {})[key];

                const an = (av === '' || av == null) ? NaN : Number(av);
                const bn = (bv === '' || bv == null) ? NaN : Number(bv);
                const bothNumeric = !Number.isNaN(an) && !Number.isNaN(bn);

                if (bothNumeric) {
                    if (an === bn) return 0;
                    return (an < bn ? -1 : 1) * dirMul;
                }

                const as = (av == null ? '' : String(av)).toLowerCase();
                const bs = (bv == null ? '' : String(bv)).toLowerCase();
                if (as === bs) return 0;
                return (as < bs ? -1 : 1) * dirMul;
            });
            return copy;
        }

        function renderTable(items) {
            const head = document.getElementById('tableHeadRow');
            const body = document.getElementById('tableBody');
            head.innerHTML = '';
            body.innerHTML = '';

            if (!selectedAgent) {
                body.innerHTML = '<tr><td style="padding:20px;color:#9fb3c8;" colspan="6">Select an agent to view data</td></tr>';
                return;
            }

            if (currentTab === 'processes') {
                addTh([
                    { label: 'Name', key: 'Name' },
                    { label: 'PID', key: 'ProcessId' },
                    { label: 'CPU(%)', key: 'CpuPct' },
                    { label: 'RAM(MB)', key: 'WorkingSetMB' },
                    { label: 'Private(MB)', key: 'PrivateMemoryMB' },
                    { label: 'Virtual(MB)', key: 'VirtualMemoryMB' },
                    { label: 'Path', key: 'ExecutablePath' },
                    { label: 'Actions', key: null }
                ]);
                const enriched = enrichProcessesForDisplay((items || []).slice(0, 500));
                enriched.forEach(p => {
                    const tr = document.createElement('tr');
                    const name = p.Name || '';
                    const pid = p.ProcessId || '';
                    const cpuPct = p.CpuPct ?? '';
                    const ws = p.WorkingSetMB ?? '';
                    const pm = p.PrivateMemoryMB ?? '';
                    const vm = p.VirtualMemoryMB ?? '';
                    const path = p.ExecutablePath || '';
                    const canRestart = !!path;

                    const cpuText = fmtPct(cpuPct, 1) || '—';
                    const wsText = fmtNum(ws, 1);
                    const pmText = fmtNum(pm, 1);
                    const vmText = fmtNum(vm, 1);

                    const cpuClass = usageClass(cpuPct, { warn: 20, bad: 50 });
                    const ramClass = usageClass(ws, { warn: 300, bad: 800 });

                    tr.innerHTML = `
                        <td>${escapeHtml(name)}</td>
                        <td>${escapeHtml(String(pid))}</td>
                        <td><span class="badge ${cpuClass}">${escapeHtml(cpuText)}</span></td>
                        <td><span class="badge ${ramClass}">${escapeHtml(wsText || '')}</span></td>
                        <td>${escapeHtml(pmText)}</td>
                        <td>${escapeHtml(vmText)}</td>
                        <td style="max-width:420px;word-break:break-all;">${escapeHtml(String(path))}</td>
                        <td>
                            <button class="btn danger" onclick="killProcess(${Number(pid)})">Kill</button>
                            <button class="btn" style="margin-left:6px;" ${canRestart ? '' : 'disabled'} onclick="restartProcess(${Number(pid)}, '${escapeAttr(path)}')">Restart</button>
                        </td>
                    `;
                    body.appendChild(tr);
                });
                return;
            }

            if (currentTab === 'services') {
                addTh(['Name','Display Name','Status','Start Type','Actions']);
                (items || []).forEach(s => {
                    const tr = document.createElement('tr');
                    const statusRaw = (s && s.Status != null) ? s.Status : '';
                    const statusStr = (typeof statusRaw === 'string') ? statusRaw : String(statusRaw);
                    const status = (statusStr || '').toLowerCase();
                    const badge = status === 'running' ? 'ok' : (status === 'stopped' ? 'bad' : 'warn');

                    tr.innerHTML = `
                        <td>${escapeHtml(s.Name || '')}</td>
                        <td>${escapeHtml(s.DisplayName || '')}</td>
                        <td><span class="badge ${badge}">${escapeHtml(statusStr || '')}</span></td>
                        <td>${escapeHtml((s && s.StartType != null) ? (typeof s.StartType === 'string' ? s.StartType : String(s.StartType)) : '')}</td>
                        <td>
                            <button class="btn" onclick="serviceAction('${escapeAttr(s.Name || '')}','start')">Start</button>
                            <button class="btn secondary" onclick="serviceAction('${escapeAttr(s.Name || '')}','stop')">Stop</button>
                            <button class="btn" onclick="serviceAction('${escapeAttr(s.Name || '')}','restart')">Restart</button>
                            <button class="btn secondary" onclick="serviceAction('${escapeAttr(s.Name || '')}','enable')">Enable</button>
                            <button class="btn secondary" onclick="serviceAction('${escapeAttr(s.Name || '')}','disable')">Disable</button>
                        </td>
                    `;
                    body.appendChild(tr);
                });
                return;
            }

            addTh(['Task Name','Task Path','State','Actions']);
            (items || []).forEach(t => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${escapeHtml(t.TaskName || '')}</td>
                    <td>${escapeHtml(t.TaskPath || '')}</td>
                    <td>${escapeHtml(t.State || '')}</td>
                    <td>
                        <button class="btn" onclick="taskAction('${escapeAttr(t.TaskName || '')}','run')">Run</button>
                        <button class="btn secondary" onclick="taskAction('${escapeAttr(t.TaskName || '')}','stop')">Stop</button>
                        <button class="btn secondary" onclick="taskAction('${escapeAttr(t.TaskName || '')}','enable')">Enable</button>
                        <button class="btn secondary" onclick="taskAction('${escapeAttr(t.TaskName || '')}','disable')">Disable</button>
                    </td>
                `;
                body.appendChild(tr);
            });

            function addTh(cols) {
                // cols can be array of strings (non-sortable) OR array of {label,key}
                if (!Array.isArray(cols)) return;

                const isObjectCols = typeof cols[0] === 'object' && cols[0] !== null;
                cols.forEach(c => {
                    const th = document.createElement('th');
                    if (!isObjectCols) {
                        th.textContent = String(c);
                        head.appendChild(th);
                        return;
                    }

                    const label = c.label || '';
                    const key = c.key || null;
                    th.textContent = label;

                    if (key) {
                        th.style.cursor = 'pointer';
                        th.title = 'Click to sort';

                        const active = sortState.tab === currentTab && sortState.key === key;
                        if (active) {
                            th.textContent = label + (sortState.dir === 'asc' ? ' ▲' : ' ▼');
                        }

                        th.onclick = () => {
                            if (sortState.tab !== currentTab) {
                                sortState.tab = currentTab;
                                sortState.key = key;
                                sortState.dir = 'desc';
                            } else if (sortState.key !== key) {
                                sortState.key = key;
                                sortState.dir = 'desc';
                            } else {
                                sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
                            }
                            renderCurrent();
                        };
                    }

                    head.appendChild(th);
                });
            }
        }

        function fmtNum(v, decimals) {
            const n = Number(v);
            if (v == null || v === '' || Number.isNaN(n)) return '';
            const d = (decimals == null ? 0 : Number(decimals));
            return n.toLocaleString(undefined, {
                minimumFractionDigits: d,
                maximumFractionDigits: d
            });
        }

        function fmtPct(v, decimals) {
            const n = Number(v);
            if (v == null || v === '' || Number.isNaN(n)) return '';
            const d = (decimals == null ? 0 : Number(decimals));
            return n.toLocaleString(undefined, {
                minimumFractionDigits: d,
                maximumFractionDigits: d
            }) + '%';
        }

        function usageClass(value, thresholds) {
            const n = Number(value);
            if (value == null || value === '' || Number.isNaN(n)) return 'warn';
            const warn = Number((thresholds || {}).warn ?? 0);
            const bad = Number((thresholds || {}).bad ?? 0);
            if (bad && n >= bad) return 'bad';
            if (warn && n >= warn) return 'warn';
            return 'ok';
        }

        function enrichProcessesForDisplay(items) {
            // If poll hasn't set clientCapturedAt yet, fall back to now.
            const nowTs = (procMeta.clientCapturedAt != null && Number.isFinite(Number(procMeta.clientCapturedAt)))
                ? Number(procMeta.clientCapturedAt)
                : Date.now();
            const cpuCount = (procMeta.cpuCount != null && !Number.isNaN(Number(procMeta.cpuCount))) ? Number(procMeta.cpuCount) : (procPrev.cpuCount || 1);

            const prevTs = procPrev.ts;
            const dtSec = (prevTs != null) ? Math.max(0.001, (nowTs - prevTs) / 1000) : null;

            const byPid = {};
            const out = (items || []).map(p => {
                const pid = Number(p.ProcessId);
                const cpu = (p.CPU == null || p.CPU === '') ? null : Number(p.CPU);

                // If server already provided CpuPct, keep it.
                const serverPct = (p.CpuPct == null || p.CpuPct === '') ? null : Number(p.CpuPct);

                let pct = null;
                if (serverPct != null && Number.isFinite(serverPct)) {
                    pct = serverPct;
                } else if (dtSec != null && !Number.isNaN(pid) && cpu != null && !Number.isNaN(cpu)) {
                    const prevCpu = procPrev.byPid[pid];
                    if (prevCpu != null && !Number.isNaN(Number(prevCpu))) {
                        const deltaCpuSec = Math.max(0, cpu - Number(prevCpu));
                        // Convert CPU time delta to percent of total CPU capacity.
                        // Windows Task Manager “CPU” column is typically 0–100 across all cores.
                        pct = (deltaCpuSec / (dtSec * Math.max(1, cpuCount))) * 100;
                        if (!Number.isFinite(pct)) pct = null;
                        if (pct != null) {
                            // Clamp to 0..100 for total CPU percent
                            pct = Math.max(0, Math.min(100, pct));
                        }
                    }
                }

                if (!Number.isNaN(pid) && cpu != null && !Number.isNaN(cpu)) {
                    byPid[pid] = cpu;
                }

                return Object.assign({}, p, {
                    CpuPct: pct
                });
            });

            // Only update prev map when we actually have CPU samples.
            // (Some environments may return null CPU for many processes.)
            const hasAnyCpu = Object.keys(byPid).length > 0;
            procPrev.ts = nowTs;
            procPrev.cpuCount = cpuCount;
            if (hasAnyCpu) {
                procPrev.byPid = byPid;
            }

            return out;
        }

        function killProcess(pid) {
            if (!confirm('Kill process PID ' + pid + '?')) return;
            document.getElementById('statusText').textContent = 'Killing process...';
            queueAction('kill_process', { pid }).then(() => refreshCurrent());
        }

        function restartProcess(pid, path) {
            if (!path) return;
            if (!confirm('Restart process PID ' + pid + '?')) return;
            document.getElementById('statusText').textContent = 'Restarting process...';
            queueAction('restart_process', { pid, path }).then(() => refreshCurrent());
        }

        function serviceAction(name, svc_action) {
            document.getElementById('statusText').textContent = 'Applying service action...';
            queueAction('service_action', { name, svc_action }).then(() => refreshCurrent());
        }

        function taskAction(name, task_action) {
            document.getElementById('statusText').textContent = 'Applying task action...';
            queueAction('task_action', { name, task_action }).then(() => refreshCurrent());
        }

        function openStartProcessModal() {
            document.getElementById('startProcModal').style.display = 'flex';
        }

        function closeStartProcessModal() {
            document.getElementById('startProcModal').style.display = 'none';
        }

        function startProcessNow() {
            const path = document.getElementById('spPath').value.trim();
            const args = document.getElementById('spArgs').value;
            const workdir = document.getElementById('spWd').value;
            if (!path) {
                alert('File Path is required');
                return;
            }
            document.getElementById('statusText').textContent = 'Starting process...';
            queueAction('start_process', { path, args, workdir })
                .then(() => {
                    closeStartProcessModal();
                    refreshCurrent();
                });
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text == null ? '' : String(text);
            return div.innerHTML;
        }

        function escapeAttr(text) {
            return (text == null ? '' : String(text)).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        setInterval(loadAgents, 10000);

        // logout handler
        <?php if (isset($_GET['logout'])): ?>
        <?php session_destroy(); ?>
        window.location.href = 'login.php';
        <?php endif; ?>
    </script>
</body>
</html>
