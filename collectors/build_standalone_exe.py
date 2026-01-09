#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build Standalone JFS SIEM Agent EXE
Creates a single EXE file with all dependencies bundled
No need to share separate Python files or install dependencies
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Fix encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def build_standalone_exe():
    """Build standalone EXE with PyInstaller"""
    
    script_dir = Path(__file__).parent
    agent_script = script_dir / "jfs_agent_simple.py"  # Use simple version
    dist_dir = script_dir / "dist_new"
    build_dir = script_dir / "build_new"
    
    print("="*70)
    print("JFS SIEM Agent - Standalone EXE Builder")
    print("="*70)
    
    # Check if agent script exists
    if not agent_script.exists():
        print(f"✗ Error: {agent_script} not found")
        return False
    
    print(f"\n✓ Agent script found: {agent_script}")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"✓ PyInstaller installed: {PyInstaller.__version__}")
    except ImportError:
        print("✗ PyInstaller not installed")
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Clean previous builds
    print("\nCleaning previous builds...")
    if build_dir.exists():
        try:
            shutil.rmtree(build_dir, ignore_errors=True)
            print(f"✓ Removed: {build_dir}")
        except:
            print(f"⚠ Could not remove: {build_dir}")
    
    if dist_dir.exists():
        try:
            shutil.rmtree(dist_dir, ignore_errors=True)
            print(f"✓ Removed: {dist_dir}")
        except:
            print(f"⚠ Could not remove: {dist_dir}")
    
    # Build command
    print("\nBuilding standalone EXE...")
    print("-" * 70)
    
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--onefile",                          # Single EXE file with all dependencies
        "--console",                          # Show console window for debugging
        "--name", "JFS_SIEM_Agent",          # EXE name
        "--hidden-import=win32evtlog",       # Hidden imports for Windows
        "--hidden-import=win32con",
        "--hidden-import=win32service",
        "--hidden-import=win32event",
        "--hidden-import=servicemanager",
        "--hidden-import=win32serviceutil",
        "--hidden-import=tkinter",           # Include Tkinter
        "--hidden-import=tkinter.ttk",       # Include Tkinter ttk
        "--collect-all=pywin32",             # Collect all pywin32 files
        "--collect-all=tkinter",             # Collect all tkinter files
        "--collect-submodules=tkinter",      # Collect tkinter submodules
        "--distpath", str(dist_dir),
        "--workpath", str(build_dir),        # Use workpath instead of buildpath
        "--specpath", str(script_dir),
        "--noupx",                           # Don't use UPX compression
        str(agent_script)
    ]
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print("-" * 70)
        print("✓ Build completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"✗ Build failed: {e}")
        return False
    
    # Check if EXE was created
    exe_path = dist_dir / "JFS_SIEM_Agent.exe"
    if not exe_path.exists():
        # Try folder location
        exe_path = dist_dir / "JFS_SIEM_Agent" / "JFS_SIEM_Agent.exe"
    if exe_path.exists():
        exe_size = exe_path.stat().st_size / (1024 * 1024)  # Size in MB
        print(f"\n✓ EXE created successfully!")
        print(f"  Location: {exe_path}")
        print(f"  Size: {exe_size:.1f} MB")
        
        # Create deployment package
        print("\nCreating deployment package...")
        package_dir = script_dir / "JFS_SIEM_Agent_Package"
        
        if package_dir.exists():
            try:
                shutil.rmtree(package_dir)
            except PermissionError:
                print(f"⚠ Could not remove old package, will overwrite files")
        
        package_dir.mkdir(exist_ok=True)
        
        # Copy EXE (with force overwrite)
        try:
            shutil.copy(exe_path, package_dir / "JFS_SIEM_Agent.exe")
        except PermissionError:
            # Try to remove and copy again
            try:
                (package_dir / "JFS_SIEM_Agent.exe").unlink()
                shutil.copy(exe_path, package_dir / "JFS_SIEM_Agent.exe")
            except:
                print(f"⚠ Could not update EXE, using existing version")
        print(f"✓ Copied EXE to: {package_dir}")
        
        # Create README
        readme_content = """# JFS SIEM Agent - Standalone Deployment

## What's Included
- JFS_SIEM_Agent.exe - Complete agent with all dependencies bundled

## Installation

### Option 1: Install as Windows Service (Recommended)

1. Open Command Prompt as Administrator
2. Run:
   ```
   JFS_SIEM_Agent.exe install
   ```
3. Start the service:
   ```
   JFS_SIEM_Agent.exe start
   ```
4. Verify:
   ```
   Get-Service JFSSIEMAgent
   ```

### Option 2: Run Directly

1. Open Command Prompt
2. Run:
   ```
   JFS_SIEM_Agent.exe
   ```

## Configuration

The agent connects to:
- **Server:** 192.168.1.100
- **Port:** 9999

To change these settings, edit the EXE configuration (see Advanced section)

## Service Management

### Start Service
```
JFS_SIEM_Agent.exe start
```

### Stop Service
```
JFS_SIEM_Agent.exe stop
```

### Remove Service
```
JFS_SIEM_Agent.exe remove
```

### Check Status
```
Get-Service JFSSIEMAgent
```

## Logs

Logs are saved to:
```
%APPDATA%\\JFS_SIEM_Agent\\logs\\jfs_agent_service.log
```

## Features

✓ Single EXE file - no dependencies to install
✓ Runs as Windows Service
✓ Persistent connection to SIEM collector
✓ Auto-reconnect on failure
✓ Continuous event collection
✓ Detailed logging
✓ Auto-starts on system reboot

## Troubleshooting

### Service won't start
- Check if collector is running (192.168.1.100:9999)
- Check firewall allows port 9999
- Check logs for errors

### No events being collected
- Verify collector is accessible
- Check Windows Event Viewer for events
- Check logs for connection errors

### Logs location
```
%APPDATA%\\JFS_SIEM_Agent\\logs\\
```

## Support

For issues, check the logs or contact your SIEM administrator.

## Version
JFS SIEM Agent v1.0 (Standalone)
"""
        
        with open(package_dir / "README.txt", "w", encoding='utf-8') as f:
            f.write(readme_content)
        print(f"✓ Created README.txt")
        
        # Create batch file for easy installation
        batch_content = """@echo off
REM JFS SIEM Agent Installation Script

echo.
echo ========================================
echo JFS SIEM Agent Installation
echo ========================================
echo.

if "%1"=="" (
    echo Usage: install.bat [install^|start^|stop^|remove]
    echo.
    echo Examples:
    echo   install.bat install  - Install as Windows Service
    echo   install.bat start    - Start the service
    echo   install.bat stop     - Stop the service
    echo   install.bat remove   - Remove the service
    echo.
    pause
    exit /b 1
)

if /i "%1"=="install" (
    echo Installing JFS SIEM Agent as Windows Service...
    JFS_SIEM_Agent.exe install
    echo.
    echo ✓ Installation complete!
    echo.
    echo To start the service, run: install.bat start
    pause
    exit /b 0
)

if /i "%1"=="start" (
    echo Starting JFS SIEM Agent service...
    JFS_SIEM_Agent.exe start
    echo.
    echo ✓ Service started!
    pause
    exit /b 0
)

if /i "%1"=="stop" (
    echo Stopping JFS SIEM Agent service...
    JFS_SIEM_Agent.exe stop
    echo.
    echo ✓ Service stopped!
    pause
    exit /b 0
)

if /i "%1"=="remove" (
    echo Removing JFS SIEM Agent service...
    JFS_SIEM_Agent.exe remove
    echo.
    echo ✓ Service removed!
    pause
    exit /b 0
)

echo Unknown command: %1
pause
exit /b 1
"""
        
        with open(package_dir / "install.bat", "w", encoding='utf-8') as f:
            f.write(batch_content)
        print(f"✓ Created install.bat")
        
        # Create PowerShell script for easy installation
        ps_content = """# JFS SIEM Agent Installation Script
# Run as Administrator

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('install', 'start', 'stop', 'remove', 'status')]
    [string]$Action
)

$exePath = Join-Path $PSScriptRoot "JFS_SIEM_Agent.exe"

if (-not (Test-Path $exePath)) {
    Write-Host "✗ Error: JFS_SIEM_Agent.exe not found" -ForegroundColor Red
    exit 1
}

Write-Host "JFS SIEM Agent - $Action" -ForegroundColor Cyan
Write-Host "=" * 50

switch ($Action) {
    'install' {
        Write-Host "Installing as Windows Service..."
        & $exePath install
        Write-Host "✓ Installation complete!" -ForegroundColor Green
    }
    'start' {
        Write-Host "Starting service..."
        & $exePath start
        Write-Host "✓ Service started!" -ForegroundColor Green
    }
    'stop' {
        Write-Host "Stopping service..."
        & $exePath stop
        Write-Host "✓ Service stopped!" -ForegroundColor Green
    }
    'remove' {
        Write-Host "Removing service..."
        & $exePath remove
        Write-Host "✓ Service removed!" -ForegroundColor Green
    }
    'status' {
        Get-Service JFSSIEMAgent -ErrorAction SilentlyContinue | Select-Object Status, DisplayName
    }
}
"""
        
        with open(package_dir / "install.ps1", "w", encoding='utf-8') as f:
            f.write(ps_content)
        print(f"✓ Created install.ps1")
        
        print(f"\n✓ Deployment package created: {package_dir}")
        print("\nPackage contents:")
        for file in package_dir.iterdir():
            size = file.stat().st_size
            if size > 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} bytes"
            print(f"  - {file.name} ({size_str})")
        
        print("\n" + "="*70)
        print("✓ BUILD COMPLETE!")
        print("="*70)
        print(f"\nReady to deploy: {package_dir}")
        print("\nTo deploy:")
        print("1. Copy entire folder to target PC")
        print("2. Run: install.bat install")
        print("3. Run: install.bat start")
        print("4. Done! Service will run continuously")
        print("\n" + "="*70)
        
        return True
    else:
        print(f"✗ EXE not found at: {exe_path}")
        return False

if __name__ == "__main__":
    success = build_standalone_exe()
    sys.exit(0 if success else 1)
