<?php
header('Content-Type: application/json');
session_start();

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/database.php';

$action = $_GET['action'] ?? '';
$agent = $_GET['agent'] ?? '';

if (empty($agent)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => 'Agent required']);
    exit;
}

$input = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = file_get_contents('php://input');
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
        $input = $decoded;
    }
}

try {
    switch ($action) {
        case 'list_processes':
            respondQueuedJson($agent, buildPsListProcesses());
            break;
        case 'system_summary':
            respondQueuedJson($agent, buildPsSystemSummary());
            break;
        case 'kill_process':
            $pid = intval($input['pid'] ?? 0);
            if ($pid <= 0) throw new Exception('pid required');
            respondQueuedJson($agent, buildPsKillProcess($pid));
            break;
        case 'restart_process':
            $pid = intval($input['pid'] ?? 0);
            $path = trim($input['path'] ?? '');
            if ($pid <= 0) throw new Exception('pid required');
            if ($path === '') throw new Exception('path required');
            respondQueuedJson($agent, buildPsRestartProcess($pid, $path));
            break;
        case 'start_process':
            $path = trim($input['path'] ?? '');
            $args = $input['args'] ?? '';
            $workdir = $input['workdir'] ?? '';
            if ($path === '') throw new Exception('path required');
            respondQueuedJson($agent, buildPsStartProcess($path, $args, $workdir));
            break;

        case 'list_services':
            respondQueuedJson($agent, buildPsListServices());
            break;
        case 'service_action':
            $name = trim($input['name'] ?? '');
            $svcAction = trim($input['svc_action'] ?? '');
            if ($name === '') throw new Exception('name required');
            if (!in_array($svcAction, ['start', 'stop', 'restart', 'enable', 'disable'], true)) throw new Exception('invalid svc_action');
            respondQueuedJson($agent, buildPsServiceAction($name, $svcAction));
            break;

        case 'list_tasks':
            respondQueuedJson($agent, buildPsListScheduledTasks());
            break;
        case 'task_action':
            $name = trim($input['name'] ?? '');
            $taskAction = trim($input['task_action'] ?? '');
            if ($name === '') throw new Exception('name required');
            if (!in_array($taskAction, ['run', 'stop', 'enable', 'disable'], true)) throw new Exception('invalid task_action');
            respondQueuedJson($agent, buildPsTaskAction($name, $taskAction));
            break;

        default:
            http_response_code(400);
            echo json_encode(['status' => 'error', 'error' => 'Invalid action']);
            exit;
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => $e->getMessage()]);
}

function respondQueuedJson($agent, $psScript) {
    $queued = queueCommandForAgent('rt:powershell_json:' . $psScript, $agent);
    if (($queued['status'] ?? '') !== 'ok') {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'error' => $queued['error'] ?? 'Failed to queue command']);
        exit;
    }

    $command_id = intval($queued['command_id']);
    echo json_encode(['status' => 'ok', 'command_id' => $command_id]);
}

function queueCommandForAgent($command, $agent) {
    $log_file = __DIR__ . '/../logs/remote_commands.log';
    @mkdir(dirname($log_file), 0777, true);
    file_put_contents($log_file, "[" . date('Y-m-d H:i:s') . "] Agent: $agent | Command: $command\n", FILE_APPEND);

    $db = getDatabase();
    if (!$db) {
        return [
            'status' => 'error',
            'error' => 'Database connection failed'
        ];
    }

    $conn = $db->getConnection();
    $agent_escaped = $conn->real_escape_string($agent);
    $command_escaped = $conn->real_escape_string($command);
    $timestamp = date('Y-m-d H:i:s');

    $sql = "INSERT INTO remote_commands (agent_name, command, status, timestamp) VALUES ('$agent_escaped', '$command_escaped', 'pending', '$timestamp')";

    if ($conn->query($sql)) {
        return [
            'status' => 'ok',
            'command_id' => $conn->insert_id
        ];
    }

    return [
        'status' => 'error',
        'error' => 'Failed to queue command: ' . $conn->error
    ];
}

function psQuote($s) {
    $s = str_replace('`', '``', $s);
    $s = str_replace('"', '`"', $s);
    return '"' . $s . '"';
}

function buildPsListProcesses() {
    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  \$cpuCount = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).NumberOfLogicalProcessors; if (-not \$cpuCount) { try { \$cpuCount = [Environment]::ProcessorCount } catch { \$cpuCount = 1 } }\n" .
        "  \$perfMap = @{}\n" .
        "  try {\n" .
        "    Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction Stop | ForEach-Object {\n" .
        "      if (\$_.IDProcess -ne \$null) {\n" .
        "        \$perfMap[[int]\$_.IDProcess] = [double]\$_.PercentProcessorTime\n" .
        "      }\n" .
        "    }\n" .
        "  } catch { }\n" .
        "  \$s0 = Get-Process -ErrorAction Stop | Select-Object ProcessName,Id,Path,CPU,WorkingSet64,PrivateMemorySize64,VirtualMemorySize64;\n" .
        "  \$p = \$s0 | ForEach-Object {\n" .
        "    \$pIdVal = [int]\$_.Id;\n" .
        "    \$pct = \$null; if (\$perfMap.ContainsKey(\$pIdVal)) { \$pct = \$perfMap[\$pIdVal] }\n" .
        "    \$cpuPctVal = \$null;\n" .
        "    if (\$pct -ne \$null) {\n" .
        "      \$norm = 0; if ([double]\$cpuCount -gt 0) { \$norm = [double]\$pct / [double]\$cpuCount }\n" .
        "      if (\$norm -lt 0) { \$norm = 0 }\n" .
        "      if (\$norm -gt 100) { \$norm = 100 }\n" .
        "      \$cpuPctVal = [math]::Round([double]\$norm, 1)\n" .
        "    }\n" .
        "    [pscustomobject]@{\n" .
        "      Name = \$_.ProcessName;\n" .
        "      ProcessId = \$pIdVal;\n" .
        "      ExecutablePath = \$_.Path;\n" .
        "      CPU = \$_.CPU;\n" .
        "      CpuPct = \$cpuPctVal;\n" .
        "      WorkingSetMB = [math]::Round(([double]\$_.WorkingSet64/1MB),1);\n" .
        "      PrivateMemoryMB = [math]::Round(([double]\$_.PrivateMemorySize64/1MB),1);\n" .
        "      VirtualMemoryMB = [math]::Round(([double]\$_.VirtualMemorySize64/1MB),1)\n" .
        "    }\n" .
        "  } | Sort-Object WorkingSetMB -Descending | Select-Object -First 200;\n" .
        "  @{ meta = @{ CpuCount = \$cpuCount; CapturedAt = (Get-Date).ToString('o') }; items = \$p } | ConvertTo-Json -Depth 4 -Compress;\n" .
        "} catch {\n" .
        "  @{ error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsSystemSummary() {
    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  \$cpu = (Get-Counter -Counter '\\Processor(_Total)\\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue;\n" .
        "  if (\$cpu -eq \$null) { \$cpu = 0 }\n" .
        "  \$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop;\n" .
        "  \$totalMem = [double]\$os.TotalVisibleMemorySize * 1KB;\n" .
        "  \$freeMem = [double]\$os.FreePhysicalMemory * 1KB;\n" .
        "  \$memPct = 0; if (\$totalMem -gt 0) { \$memPct = ((\$totalMem-\$freeMem)/\$totalMem)*100 }\n" .
        "  \$drives = Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" -ErrorAction SilentlyContinue | ForEach-Object {\n" .
        "    \$size = [double]\$_.Size;\n" .
        "    \$free = [double]\$_.FreeSpace;\n" .
        "    \$usedPct = 0; if (\$size -gt 0) { \$usedPct = ((\$size-\$free)/\$size)*100 }\n" .
        "    [pscustomobject]@{ Name = \$_.DeviceID; UsedPct = [math]::Round(\$usedPct,1); FreeGB = [math]::Round((\$free/1GB),1); SizeGB = [math]::Round((\$size/1GB),1) }\n" .
        "  };\n" .
        "  [pscustomobject]@{ CpuPct = [math]::Round([double]\$cpu,1); MemPct = [math]::Round([double]\$memPct,1); Drives = \$drives; CapturedAt = (Get-Date).ToString('o') } | ConvertTo-Json -Depth 4 -Compress;\n" .
        "} catch {\n" .
        "  @{ error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsKillProcess($pid) {
    $pid = intval($pid);
    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  \$targetPid = [int]$pid;\n" .
        "  Stop-Process -Id \$targetPid -Force -ErrorAction Stop;\n" .
        "  [pscustomobject]@{ ok = \$true; action = 'kill'; pid = \$targetPid } | ConvertTo-Json -Compress;\n" .
        "} catch {\n" .
        "  [pscustomobject]@{ ok = \$false; action = 'kill'; pid = [int]$pid; error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsRestartProcess($pid, $path) {
    $pid = intval($pid);
    $qpath = psQuote($path);
    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  \$targetPid = [int]$pid;\n" .
        "  Stop-Process -Id \$targetPid -Force -ErrorAction Stop;\n" .
        "  \$p = Start-Process -FilePath $qpath -PassThru;\n" .
        "  [pscustomobject]@{ ok = \$true; action = 'restart'; old_pid = \$targetPid; new_pid = \$p.Id; path = $qpath } | ConvertTo-Json -Compress;\n" .
        "} catch {\n" .
        "  [pscustomobject]@{ ok = \$false; action = 'restart'; old_pid = [int]$pid; error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsStartProcess($path, $args, $workdir) {
    $qpath = psQuote($path);
    $qargs = psQuote((string)$args);
    $qwd = trim((string)$workdir) === '' ? '' : psQuote((string)$workdir);

    $wdPart = $qwd === '' ? '' : " -WorkingDirectory $qwd";

    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  \$p = Start-Process -FilePath $qpath -ArgumentList $qargs$wdPart -PassThru;\n" .
        "  [pscustomobject]@{ ok = \$true; action = 'start'; pid = \$p.Id } | ConvertTo-Json -Compress;\n" .
        "} catch {\n" .
        "  [pscustomobject]@{ ok = \$false; action = 'start'; error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsListServices() {
    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  \$s = Get-Service -ErrorAction Stop | Select-Object Name,DisplayName,Status,StartType;\n" .
        "  \$s | ConvertTo-Json -Depth 3 -Compress;\n" .
        "} catch {\n" .
        "  @{ error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsServiceAction($name, $svcAction) {
    $qname = psQuote($name);

    $actionScript = '';
    switch ($svcAction) {
        case 'start':
            $actionScript = "Start-Service -Name $qname -ErrorAction Stop";
            break;
        case 'stop':
            $actionScript = "Stop-Service -Name $qname -Force -ErrorAction Stop";
            break;
        case 'restart':
            $actionScript = "Restart-Service -Name $qname -Force -ErrorAction Stop";
            break;
        case 'enable':
            $actionScript = "Set-Service -Name $qname -StartupType Automatic -ErrorAction Stop";
            break;
        case 'disable':
            $actionScript = "Set-Service -Name $qname -StartupType Disabled -ErrorAction Stop";
            break;
    }

    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  $actionScript;\n" .
        "  [pscustomobject]@{ ok = \$true; action = $qname; svc_action = '$svcAction'; name = $qname } | ConvertTo-Json -Compress;\n" .
        "} catch {\n" .
        "  [pscustomobject]@{ ok = \$false; svc_action = '$svcAction'; name = $qname; error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsListScheduledTasks() {
    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  \$t = Get-ScheduledTask -ErrorAction Stop | Select-Object TaskName,TaskPath,State;\n" .
        "  \$t | ConvertTo-Json -Depth 3 -Compress;\n" .
        "} catch {\n" .
        "  @{ error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}

function buildPsTaskAction($name, $taskAction) {
    $qname = psQuote($name);

    $actionScript = '';
    switch ($taskAction) {
        case 'run':
            $actionScript = "Start-ScheduledTask -TaskName $qname -ErrorAction Stop";
            break;
        case 'stop':
            $actionScript = "Stop-ScheduledTask -TaskName $qname -ErrorAction Stop";
            break;
        case 'enable':
            $actionScript = "Enable-ScheduledTask -TaskName $qname -ErrorAction Stop";
            break;
        case 'disable':
            $actionScript = "Disable-ScheduledTask -TaskName $qname -ErrorAction Stop";
            break;
    }

    return "try {\n" .
        "  \$ErrorActionPreference = 'Stop';\n" .
        "  \$ProgressPreference = 'SilentlyContinue';\n" .
        "  try { \$PSStyle.OutputRendering = 'PlainText' } catch {}\n" .
        "  $actionScript;\n" .
        "  [pscustomobject]@{ ok = \$true; task_action = '$taskAction'; name = $qname } | ConvertTo-Json -Compress;\n" .
        "} catch {\n" .
        "  [pscustomobject]@{ ok = \$false; task_action = '$taskAction'; name = $qname; error = \$_.Exception.Message } | ConvertTo-Json -Compress;\n" .
        "}";
}
