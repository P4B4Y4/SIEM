$taskName = "JFS SIEM Event Collector"
$scriptPath = "d:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\start_scheduler.bat"

Write-Host "Creating Task Scheduler task..."

# Delete old task if exists
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Create action
$action = New-ScheduledTaskAction -Execute $scriptPath -WorkingDirectory (Split-Path $scriptPath)

# Create trigger: At startup
$trigger = New-ScheduledTaskTrigger -AtStartup

# Create settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# Register task with SYSTEM account and highest privileges
$task = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -User "SYSTEM" -Force

Write-Host "Task created successfully!"
Write-Host "Status: Ready"
Write-Host "Run As: SYSTEM"
Write-Host "Trigger: At system startup"
