# Create JFS SIEM Event Collector Task with proper settings

$taskName = "JFS SIEM Event Collector"
$scriptPath = "d:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\start_scheduler.bat"
$taskDescription = "Automatically collect Windows Event Logs for JFS SIEM"

Write-Host "Creating Task Scheduler task: $taskName"
Write-Host "Script: $scriptPath"
Write-Host ""

# Create trigger 1: At startup
$trigger1 = New-ScheduledTaskTrigger -AtStartup
Write-Host "✓ Trigger 1: At startup"

# Create trigger 2: Every 5 minutes, indefinitely
$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 36500)
Write-Host "✓ Trigger 2: Every 5 minutes"

# Create action
$action = New-ScheduledTaskAction -Execute $scriptPath -WorkingDirectory (Split-Path $scriptPath)
Write-Host "✓ Action: Execute batch file"

# Create settings with highest privileges
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RunWithoutNetwork `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0 -Minutes 30)

Write-Host "✓ Settings: Highest privileges, 30 min timeout"

# Register the task with SYSTEM account
try {
    $task = Register-ScheduledTask `
        -TaskName $taskName `
        -Trigger @($trigger1, $trigger2) `
        -Action $action `
        -Settings $settings `
        -Description $taskDescription `
        -RunLevel Highest `
        -User "SYSTEM" `
        -Force `
        -ErrorAction Stop
    
    Write-Host ""
    Write-Host "✓✓✓ Task created successfully! ✓✓✓"
    Write-Host ""
    Write-Host "Task Details:"
    Write-Host "  Name: $taskName"
    Write-Host "  Status: Ready"
    Write-Host "  Run As: SYSTEM (highest privileges)"
    Write-Host "  Triggers: At startup + Every 5 minutes"
    Write-Host ""
    Write-Host "The task will start collecting events immediately!"
    
} catch {
    Write-Host "✗ Error creating task: $_"
    exit 1
}
