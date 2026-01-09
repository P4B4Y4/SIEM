#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Build JFS SIEM Agent GUI as standalone EXE
Uses PyInstaller to create a single executable file
"""

import subprocess
import sys
import os
import shutil

def main():
    """Build the agent GUI EXE"""
    
    # Get current directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("\n" + "="*70)
    print("JFS SIEM - Building Agent GUI EXE")
    print("="*70)
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("\n✗ PyInstaller not installed")
        print("Install with: pip install pyinstaller")
        sys.exit(1)
    
    # Clean old builds
    print("\nCleaning old build files...")
    for folder in ['dist', 'build']:
        path = os.path.join(script_dir, folder)
        if os.path.exists(path):
            try:
                shutil.rmtree(path, ignore_errors=True)
                print(f"Removed: {folder}")
            except Exception as e:
                print(f"Warning: Could not remove {folder}: {e}")
                # Try renaming instead
                try:
                    os.rename(path, path + '_old')
                    print(f"Renamed {folder} to {folder}_old")
                except:
                    pass
    
    # Remove old spec files
    try:
        for file in os.listdir(script_dir):
            if file.endswith('.spec'):
                try:
                    os.remove(os.path.join(script_dir, file))
                    print(f"  Removed: {file}")
                except:
                    pass
    except:
        pass
    
    # Build command
    print("\nBuilding EXE with PyInstaller...")
    print("Using: jfs_agent_service.py (REAL Windows Service with persistence)")
    
    # Copy the service file from Ubuntu folder
    ubuntu_service = r"d:\soft\UBUNTU\JFS-SIEM-COMPLETE-FIXED\JFS-SIEM-FIXED\python\collectors\jfs_siem_service_only.py"
    local_service = os.path.join(script_dir, "jfs_siem_service_only.py")
    
    if os.path.exists(ubuntu_service):
        shutil.copy(ubuntu_service, local_service)
        print(f"Copied service file from Ubuntu folder")
    
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--onefile',
        '--name=JFS_SIEM_Agent',
        '--distpath=dist_final',
        '--hidden-import=win32serviceutil',
        '--hidden-import=win32service',
        '--hidden-import=win32event',
        '--hidden-import=servicemanager',
        'jfs_siem_service_only.py'
    ]
    
    # Run PyInstaller
    result = subprocess.run(cmd, cwd=script_dir)
    
    if result.returncode == 0:
        exe_path = os.path.join(script_dir, 'dist_final', 'JFS_SIEM_Agent.exe')
        if os.path.exists(exe_path):
            exe_size = os.path.getsize(exe_path) / (1024 * 1024)
            print("\n" + "="*70)
            print("[OK] BUILD SUCCESSFUL - WITH PERSISTENCE FEATURES!")
            print("="*70)
            print(f"EXE Location: {exe_path}")
            print(f"File Size: {exe_size:.1f} MB")
            print("\nFeatures Included:")
            print("[+] Remote access (screenshot, command execution)")
            print("[+] Windows Service installation")
            print("[+] Persistence (works after reboot)")
            print("[+] Runs even after EXE is closed")
            print("[+] Auto-restart on crash")
            print("[+] Modern GUI interface")
            print("\nNext steps:")
            print("1. Copy JFS_SIEM_Agent.exe to remote PC")
            print("2. Double-click to run")
            print("3. Enter collector IP: 192.168.1.52")
            print("4. Click 'Install Service' for persistence")
            print("5. Click 'Start Agent'")
            print("6. Service runs 24/7, even after reboot!")
            print("="*70 + "\n")
        else:
            print("\n[-] BUILD FAILED: EXE not found")
            sys.exit(1)
    else:
        print("\n[-] BUILD FAILED")
        sys.exit(1)

if __name__ == '__main__':
    main()
