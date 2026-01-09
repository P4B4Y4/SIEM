param(
    [string]$SiteRoot = "D:\\xamp\\htdocs\\SIEM",
    [string]$ServiceRoot = "D:\\xamp\\htdocs\\SIEM\\services",
    [string]$PhpPath = "",
    [switch]$NoStart,
    [switch]$NoInstall
)

$ErrorActionPreference = 'Stop'

function Find-Php {
    param([string]$Preferred)
    if ($Preferred -and (Test-Path $Preferred)) { return $Preferred }

    $candidates = @(
        "D:\\xamp\\php\\php.exe",
        "C:\\xamp\\php\\php.exe",
        "C:\\xampp\\php\\php.exe",
        "D:\\xampp\\php\\php.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }

    $cmd = Get-Command php -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
        return $cmd.Source
    }

    throw "php.exe not found. Pass -PhpPath 'D:\\xamp\\php\\php.exe'"
}

function Ensure-Dir { param([string]$p) if (!(Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null } }

function Write-WinSWConfig {
    param(
        [string]$ServiceDir,
        [string]$ServiceId,
        [string]$DisplayName,
        [string]$Description,
        [string]$Executable,
        [string]$Arguments
    )

    $xmlPath = Join-Path $ServiceDir ($ServiceId + '.xml')
    $logDir = Join-Path $ServiceDir 'logs'
    Ensure-Dir $logDir

    $xml = @"
<service>
  <id>$ServiceId</id>
  <name>$DisplayName</name>
  <description>$Description</description>
  <executable>$Executable</executable>
  <arguments>$Arguments</arguments>
  <logpath>$logDir</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
  <onfailure action="restart" delay="5 sec" />
</service>
"@

    Set-Content -Path $xmlPath -Value $xml -Encoding UTF8
}

$PhpPath = Find-Php -Preferred $PhpPath
Write-Host "SiteRoot: $SiteRoot"
Write-Host "ServiceRoot: $ServiceRoot"
Write-Host "Using PHP: $PhpPath"

$winswSourceExe = Join-Path $SiteRoot 'collectors\agent_service_winsw\JFSSIEMAgentService.exe'
if (!(Test-Path $winswSourceExe)) {
    throw "WinSW exe not found at $winswSourceExe"
}

Ensure-Dir $ServiceRoot

$services = @(
    @{
        Id='SIEMEmailSender';
        Name='SIEM Email Sender';
        Desc='Sends SIEM alert emails in background (send_pending loop)';
        Script=Join-Path $SiteRoot 'cron\email_sender_worker.php'
    },
    @{
        Id='SIEMFortinetSyslog';
        Name='SIEM Fortinet Syslog Listener';
        Desc='Receives Fortinet syslog over UDP 514 and stores events';
        Script=Join-Path $SiteRoot 'syslog-listener.php'
    },
    @{
        Id='SIEMEsetSyslog';
        Name='SIEM ESET Syslog Listener';
        Desc='Receives ESET syslog over UDP 6514 and stores events';
        Script=Join-Path $SiteRoot 'eset-syslog-listener.php'
    }
)

foreach ($s in $services) {
    if (!(Test-Path $s.Script)) {
        throw "Missing script: $($s.Script)"
    }

    $svcDir = Join-Path $ServiceRoot $s.Id
    Ensure-Dir $svcDir

    $svcExe = Join-Path $svcDir ($s.Id + '.exe')
    Copy-Item -Force -Path $winswSourceExe -Destination $svcExe

    $args = "-f \"$($s.Script)\""
    Write-WinSWConfig -ServiceDir $svcDir -ServiceId $s.Id -DisplayName $s.Name -Description $s.Desc -Executable $PhpPath -Arguments $args
    $svcXml = Join-Path $svcDir ($s.Id + '.xml')

    if ($NoInstall) {
        Write-Host "Prepared $($s.Id):"
        Write-Host "  EXE: $svcExe"
        Write-Host "  XML: $svcXml"
        continue
    }

    Write-Host "Installing $($s.Id)..."
    & $svcExe install

    if (!$NoStart) {
        Write-Host "Starting $($s.Id)..."
        & $svcExe start
    }
}

Write-Host "Done. Services installed under: $ServiceRoot"
Write-Host "You can manage them with: services.msc"
