<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
header('Content-Type: application/json');

if (!isset($_SESSION['user_id']) && !isset($_SESSION['username'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/../config/config.php';

$refresh = isset($_GET['refresh']) && $_GET['refresh'] === '1';
$ttl_seconds = isset($_GET['ttl']) ? max(10, min(3600, (int)$_GET['ttl'])) : 300; // 5 min default

$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Database connection failed']);
    exit;
}

$db->query("CREATE TABLE IF NOT EXISTS agent_resource_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent VARCHAR(128) NOT NULL,
    cpu_percent FLOAT NULL,
    mem_percent FLOAT NULL,
    mem_used_mb INT NULL,
    mem_total_mb INT NULL,
    disk_percent FLOAT NULL,
    disk_free_gb FLOAT NULL,
    disk_total_gb FLOAT NULL,
    status VARCHAR(32) NULL,
    last_command_id INT NULL,
    last_requested_at DATETIME NULL,
    last_reported_at DATETIME NULL,
    raw_output MEDIUMTEXT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_agent (agent)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// Agent list (same logic as agent-ai-summary)
$agents = [];
$agentQuery = "
    SELECT agent AS agent, MAX(timestamp) AS last_seen
    FROM (
        SELECT agent_id AS agent, timestamp FROM security_events WHERE agent_id IS NOT NULL AND agent_id <> ''
        UNION ALL
        SELECT source_ip AS agent, timestamp FROM security_events WHERE (agent_id IS NULL OR agent_id = '') AND source_ip IS NOT NULL AND source_ip <> ''
        UNION ALL
        SELECT user_account AS agent, timestamp FROM security_events WHERE (agent_id IS NULL OR agent_id = '') AND (source_ip IS NULL OR source_ip = '') AND user_account IS NOT NULL AND user_account <> ''
    ) t
    GROUP BY agent
    ORDER BY last_seen DESC
    LIMIT 15
";
$resAgents = $db->query($agentQuery);
if ($resAgents) {
    while ($row = $resAgents->fetch_assoc()) {
        $agents[] = [
            'agent' => (string)($row['agent'] ?? ''),
            'last_seen' => (string)($row['last_seen'] ?? '')
        ];
    }
}

$now = time();

// Helpers
$parseNumber = function ($s) {
    if (!is_string($s)) return null;
    if (!preg_match('/-?\d+(?:\.\d+)?/', $s, $m)) return null;
    return (float)$m[0];
};

$parseOutput = function (string $output) use ($parseNumber) {
    $out = trim($output);
    $result = [
        'cpu_percent' => null,
        'mem_percent' => null,
        'mem_used_mb' => null,
        'mem_total_mb' => null,
        'disk_percent' => null,
        'disk_free_gb' => null,
        'disk_total_gb' => null
    ];
    if ($out === '') return $result;

    // If agent returned multiple lines, keep the one containing our marker
    if (strpos($out, "\n") !== false) {
        foreach (explode("\n", $out) as $ln) {
            $ln = trim($ln);
            if ($ln === '') continue;
            if (strpos($ln, 'JFS_RES|') !== false || $ln[0] === '{') {
                $out = $ln;
                break;
            }
        }
    }

    // 1) Our marker format: JFS_RES|cpu=..|mem=..|...
    if (strpos($out, 'JFS_RES|') !== false) {
        $parts = explode('|', $out);
        foreach ($parts as $p) {
            if (strpos($p, '=') === false) continue;
            [$k, $v] = explode('=', $p, 2);
            $k = trim($k);
            $v = trim($v);
            if ($k === 'cpu') $result['cpu_percent'] = $parseNumber($v);
            if ($k === 'mem') $result['mem_percent'] = $parseNumber($v);
            if ($k === 'memUsedMB') $result['mem_used_mb'] = (int)round((float)$parseNumber($v));
            if ($k === 'memTotalMB') $result['mem_total_mb'] = (int)round((float)$parseNumber($v));
            if ($k === 'disk') $result['disk_percent'] = $parseNumber($v);
            if ($k === 'diskFreeGB') $result['disk_free_gb'] = $parseNumber($v);
            if ($k === 'diskTotalGB') $result['disk_total_gb'] = $parseNumber($v);
        }
        return $result;
    }

    // 2) JSON format from rt:powershell_json wrapper
    if ($out !== '' && ($out[0] === '{' || $out[0] === '[')) {
        $j = json_decode($out, true);
        if (is_array($j) && !isset($j['error'])) {
            if (isset($j['CpuPct'])) $result['cpu_percent'] = (float)$j['CpuPct'];
            if (isset($j['MemPct'])) $result['mem_percent'] = (float)$j['MemPct'];
            if (isset($j['MemUsedMB'])) $result['mem_used_mb'] = (int)$j['MemUsedMB'];
            if (isset($j['MemTotalMB'])) $result['mem_total_mb'] = (int)$j['MemTotalMB'];
            if (isset($j['DiskUsedPct'])) $result['disk_percent'] = (float)$j['DiskUsedPct'];
            if (isset($j['DiskFreeGB'])) $result['disk_free_gb'] = (float)$j['DiskFreeGB'];
            if (isset($j['DiskTotalGB'])) $result['disk_total_gb'] = (float)$j['DiskTotalGB'];
        }
    }
    return $result;
};

// Fetch/refresh cache per agent
$outAgents = [];
foreach ($agents as $a) {
    $agent = $a['agent'];
    if ($agent === '') continue;

    $cacheRow = null;
    $stmt = $db->prepare('SELECT cpu_percent, mem_percent, mem_used_mb, mem_total_mb, disk_percent, disk_free_gb, disk_total_gb, status, last_command_id, last_requested_at, last_reported_at, updated_at FROM agent_resource_cache WHERE agent=? LIMIT 1');
    if ($stmt) {
        $stmt->bind_param('s', $agent);
        $stmt->execute();
        $rs = $stmt->get_result();
        if ($rs && $rs->num_rows > 0) {
            $cacheRow = $rs->fetch_assoc();
        }
        $stmt->close();
    }

    $cachedFresh = false;
    if ($cacheRow && !empty($cacheRow['updated_at'])) {
        $t = strtotime((string)$cacheRow['updated_at']);
        if ($t && ($now - $t) <= $ttl_seconds) {
            $cachedFresh = true;
        }
    }

    // If cache exists and has a pending command, try to sync completion/output
    if ($cacheRow && !empty($cacheRow['last_command_id'])) {
        $cmdId = (int)$cacheRow['last_command_id'];
        if ($cmdId > 0) {
            $cmdStmt = $db->prepare('SELECT status, output, error, completed_at FROM remote_commands WHERE id=? LIMIT 1');
            if ($cmdStmt) {
                $cmdStmt->bind_param('i', $cmdId);
                $cmdStmt->execute();
                $cmdRs = $cmdStmt->get_result();
                if ($cmdRs && $cmdRs->num_rows > 0) {
                    $cmd = $cmdRs->fetch_assoc();
                    $status = (string)($cmd['status'] ?? '');
                    $completedAt = (string)($cmd['completed_at'] ?? '');
                    $output = (string)($cmd['output'] ?? '');
                    $error = (string)($cmd['error'] ?? '');

                    if ($completedAt !== '' && ($output !== '' || $error !== '')) {
                        $parsed = $parseOutput($output);
                        $raw = $output !== '' ? $output : $error;
                        if (strlen($raw) > 2000) {
                            $raw = substr($raw, 0, 2000);
                        }

                        $cpu = $parsed['cpu_percent'];
                        $mem = $parsed['mem_percent'];
                        $memUsed = $parsed['mem_used_mb'];
                        $memTotal = $parsed['mem_total_mb'];
                        $disk = $parsed['disk_percent'];
                        $diskFree = $parsed['disk_free_gb'];
                        $diskTotal = $parsed['disk_total_gb'];

                        $cpuS = $cpu === null ? null : (string)$cpu;
                        $memS = $mem === null ? null : (string)$mem;
                        $memUsedS = $memUsed === null ? null : (string)$memUsed;
                        $memTotalS = $memTotal === null ? null : (string)$memTotal;
                        $diskS = $disk === null ? null : (string)$disk;
                        $diskFreeS = $diskFree === null ? null : (string)$diskFree;
                        $diskTotalS = $diskTotal === null ? null : (string)$diskTotal;

                        $lr = $cacheRow['last_requested_at'] ?? null;
                        $reported = $completedAt;

                        $up = $db->prepare('INSERT INTO agent_resource_cache (agent, cpu_percent, mem_percent, mem_used_mb, mem_total_mb, disk_percent, disk_free_gb, disk_total_gb, status, last_command_id, last_requested_at, last_reported_at, raw_output)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                            ON DUPLICATE KEY UPDATE cpu_percent=VALUES(cpu_percent), mem_percent=VALUES(mem_percent), mem_used_mb=VALUES(mem_used_mb), mem_total_mb=VALUES(mem_total_mb), disk_percent=VALUES(disk_percent), disk_free_gb=VALUES(disk_free_gb), disk_total_gb=VALUES(disk_total_gb), status=VALUES(status), last_reported_at=VALUES(last_reported_at), raw_output=VALUES(raw_output)');
                        if ($up) {
                            $cmdIdS = (string)$cmdId;
                            $up->bind_param('sssssssssisss', $agent, $cpuS, $memS, $memUsedS, $memTotalS, $diskS, $diskFreeS, $diskTotalS, $status, $cmdIdS, $lr, $reported, $raw);
                            $up->execute();
                            $up->close();
                        }

                        // Reload cacheRow
                        $stmt2 = $db->prepare('SELECT cpu_percent, mem_percent, mem_used_mb, mem_total_mb, disk_percent, disk_free_gb, disk_total_gb, status, last_command_id, last_requested_at, last_reported_at, updated_at FROM agent_resource_cache WHERE agent=? LIMIT 1');
                        if ($stmt2) {
                            $stmt2->bind_param('s', $agent);
                            $stmt2->execute();
                            $rs2 = $stmt2->get_result();
                            if ($rs2 && $rs2->num_rows > 0) {
                                $cacheRow = $rs2->fetch_assoc();
                            }
                            $stmt2->close();
                        }
                    }
                }
                $cmdStmt->close();
            }
        }
    }

    // Enqueue a fresh resource command if requested or cache stale
    if ($refresh || !$cachedFresh) {
        // Rate-limit: don't enqueue more often than 60s per agent
        $canSend = true;
        if ($cacheRow && !empty($cacheRow['last_requested_at'])) {
            $rt = strtotime((string)$cacheRow['last_requested_at']);
            if ($rt && ($now - $rt) < 60) {
                $canSend = false;
            }
        }

        if ($canSend) {
            // Use the exact known-good script format that already worked in your environment.
            // IMPORTANT: build with single quotes so PHP doesn't eat PowerShell $variables.
            $cmd = <<<'CMD'
rt:powershell_json:try {
  $ErrorActionPreference = 'Stop';
  $ProgressPreference = 'SilentlyContinue';
  try { $PSStyle.OutputRendering = 'PlainText' } catch {}
  $cpu = (Get-Counter -Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue;
  if ($cpu -eq $null) { $cpu = 0 }
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop;
  $totalMem = [double]$os.TotalVisibleMemorySize * 1KB;
  $freeMem = [double]$os.FreePhysicalMemory * 1KB;
  $memPct = 0; if ($totalMem -gt 0) { $memPct = (($totalMem-$freeMem)/$totalMem)*100 }
  $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue;
  $diskTotal = 0; $diskFree = 0; $diskUsedPct = 0;
  if ($drive) {
    $diskTotal = [double]$drive.Size;
    $diskFree = [double]$drive.FreeSpace;
    if ($diskTotal -gt 0) { $diskUsedPct = (($diskTotal-$diskFree)/$diskTotal)*100 }
  }
  [pscustomobject]@{
    CpuPct = [math]::Round([double]$cpu,1);
    MemPct = [math]::Round([double]$memPct,1);
    MemUsedMB = [math]::Round((($totalMem-$freeMem)/1MB),0);
    MemTotalMB = [math]::Round(($totalMem/1MB),0);
    DiskUsedPct = [math]::Round([double]$diskUsedPct,1);
    DiskFreeGB = [math]::Round(($diskFree/1GB),1);
    DiskTotalGB = [math]::Round(($diskTotal/1GB),1);
    CapturedAt = (Get-Date).ToString('o')
  } | ConvertTo-Json -Depth 3 -Compress;
} catch {
  @{ error = $_.Exception.Message } | ConvertTo-Json -Compress;
}
CMD;

            $ins = $db->prepare("INSERT INTO remote_commands (agent_name, command, timestamp, status) VALUES (?, ?, NOW(), 'pending')");
            if ($ins) {
                $ins->bind_param('ss', $agent, $cmd);
                if ($ins->execute()) {
                    $cmdId = (int)$db->insert_id;
                    $up = $db->prepare('INSERT INTO agent_resource_cache (agent, status, last_command_id, last_requested_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE status=VALUES(status), last_command_id=VALUES(last_command_id), last_requested_at=VALUES(last_requested_at)');
                    if ($up) {
                        $pending = 'pending';
                        $up->bind_param('ssi', $agent, $pending, $cmdId);
                        $up->execute();
                        $up->close();
                    }
                }
                $ins->close();
            }
        }
    }

    $outAgents[] = [
        'agent' => $agent,
        'last_seen' => $a['last_seen'],
        'cpu_percent' => $cacheRow['cpu_percent'] ?? null,
        'mem_percent' => $cacheRow['mem_percent'] ?? null,
        'mem_used_mb' => $cacheRow['mem_used_mb'] ?? null,
        'mem_total_mb' => $cacheRow['mem_total_mb'] ?? null,
        'disk_percent' => $cacheRow['disk_percent'] ?? null,
        'disk_free_gb' => $cacheRow['disk_free_gb'] ?? null,
        'disk_total_gb' => $cacheRow['disk_total_gb'] ?? null,
        'status' => $cacheRow['status'] ?? null,
        'last_requested_at' => $cacheRow['last_requested_at'] ?? null,
        'last_reported_at' => $cacheRow['last_reported_at'] ?? null,
        'updated_at' => $cacheRow['updated_at'] ?? null
    ];
}

echo json_encode([
    'success' => true,
    'refresh' => $refresh,
    'ttl_seconds' => $ttl_seconds,
    'agents' => $outAgents
]);

$db->close();
