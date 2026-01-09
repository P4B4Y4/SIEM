# Simple Task Scheduler creation script

$taskName = "JFS SIEM Event Collector"
$scriptPath = "d:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\start_scheduler.bat"

Write-Host "Creating Task Scheduler task..."

# Delete old task if exists
try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "✓ Old task removed"
} catch {}

# Create action
$action = New-ScheduledTaskAction -Execute $scriptPath -WorkingDirectory (Split-Path $scriptPath)

# Create trigger: At startup
$trigger = New-ScheduledTaskTrigger -AtStartup

# Create settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# Register task with SYSTEM account and highest privileges
$task = Register-ScheduledTask -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -RunLevel Highest `
    -User "SYSTEM" `
    -Force

Write-Host ""
Write-Host "Task created successfully!"
Write-Host ""
Write-Host "The task will run:"
Write-Host "  - At system startup"
Write-Host "  - With highest privileges (SYSTEM account)"
Write-Host "  - Automatically collecting events"
Write-Host ""
Write-Host "To manually run it now, use:"
Write-Host "  schtasks /run /TN `"JFS SIEM Event Collector`""
