<?php

$siteRoot = realpath(__DIR__ . '/..');
if ($siteRoot === false) {
    fwrite(STDERR, "Unable to resolve site root\n");
    exit(1);
}

$winswSourceExe = $siteRoot . DIRECTORY_SEPARATOR . 'collectors' . DIRECTORY_SEPARATOR . 'agent_service_winsw' . DIRECTORY_SEPARATOR . 'JFSSIEMAgentService.exe';
if (!file_exists($winswSourceExe)) {
    fwrite(STDERR, "WinSW exe not found at: $winswSourceExe\n");
    exit(1);
}

$phpPath = PHP_BINARY;
if (!is_string($phpPath) || $phpPath === '') {
    fwrite(STDERR, "Unable to determine PHP binary path\n");
    exit(1);
}

$outRoot = $siteRoot . DIRECTORY_SEPARATOR . 'services_build';

$services = [
    [
        'id' => 'SIEMEmailSender',
        'name' => 'SIEM Email Sender',
        'desc' => 'Sends SIEM alert emails in background (send_pending loop)',
        'script' => $siteRoot . DIRECTORY_SEPARATOR . 'cron' . DIRECTORY_SEPARATOR . 'email_sender_worker.php',
    ],
    [
        'id' => 'SIEMFortinetSyslog',
        'name' => 'SIEM Fortinet Syslog Listener',
        'desc' => 'Receives Fortinet syslog over UDP 514 and stores events',
        'script' => $siteRoot . DIRECTORY_SEPARATOR . 'syslog-listener.php',
    ],
    [
        'id' => 'SIEMEsetSyslog',
        'name' => 'SIEM ESET Syslog Listener',
        'desc' => 'Receives ESET syslog over UDP 6514 and stores events',
        'script' => $siteRoot . DIRECTORY_SEPARATOR . 'eset-syslog-listener.php',
    ],
];

function ensure_dir(string $p): void {
    if (!is_dir($p)) {
        if (!mkdir($p, 0777, true) && !is_dir($p)) {
            throw new RuntimeException("Failed to create directory: $p");
        }
    }
}

function xml_escape(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_XML1, 'UTF-8');
}

try {
    ensure_dir($outRoot);

    foreach ($services as $s) {
        if (!file_exists($s['script'])) {
            throw new RuntimeException('Missing script: ' . $s['script']);
        }

        $svcDir = $outRoot . DIRECTORY_SEPARATOR . $s['id'];
        ensure_dir($svcDir);
        ensure_dir($svcDir . DIRECTORY_SEPARATOR . 'logs');

        $svcExe = $svcDir . DIRECTORY_SEPARATOR . $s['id'] . '.exe';
        if (!copy($winswSourceExe, $svcExe)) {
            throw new RuntimeException('Failed to copy exe to: ' . $svcExe);
        }

        $args = '-f "' . $s['script'] . '"';
        $xmlPath = $svcDir . DIRECTORY_SEPARATOR . $s['id'] . '.xml';
        $logDir = $svcDir . DIRECTORY_SEPARATOR . 'logs';

        $xml = "<service>\n" .
            "  <id>" . xml_escape($s['id']) . "</id>\n" .
            "  <name>" . xml_escape($s['name']) . "</name>\n" .
            "  <description>" . xml_escape($s['desc']) . "</description>\n" .
            "  <executable>" . xml_escape($phpPath) . "</executable>\n" .
            "  <arguments>" . xml_escape($args) . "</arguments>\n" .
            "  <logpath>" . xml_escape($logDir) . "</logpath>\n" .
            "  <log mode=\"roll-by-size\">\n" .
            "    <sizeThreshold>10240</sizeThreshold>\n" .
            "    <keepFiles>5</keepFiles>\n" .
            "  </log>\n" .
            "  <onfailure action=\"restart\" delay=\"5 sec\" />\n" .
            "</service>\n";

        if (file_put_contents($xmlPath, $xml) === false) {
            throw new RuntimeException('Failed to write xml: ' . $xmlPath);
        }

        echo "Built:\n";
        echo "  EXE: $svcExe\n";
        echo "  XML: $xmlPath\n\n";
    }

    echo "Done. Output folder: $outRoot\n";
} catch (Throwable $e) {
    fwrite(STDERR, "ERROR: " . $e->getMessage() . "\n");
    exit(1);
}
