#!/usr/bin/env python3
"""
Build enhanced SIEM Agent EXE with PyInstaller
Includes comprehensive event collection
"""

import os
import subprocess
import sys

def build_exe():
    """Build standalone EXE"""
    
    print("=" * 70)
    print("JFS SIEM Agent Enhanced - Building EXE")
    print("=" * 70)
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("ERROR: PyInstaller not installed")
        print("Run: pip install PyInstaller")
        sys.exit(1)
    
    # Build command using python -m PyInstaller
    build_cmd = [
        sys.executable,
        '-m',
        'PyInstaller',
        '--onefile',
        '--windowed',
        '--icon=NONE',
        '--add-data=.;.',
        '--hidden-import=win32evtlog',
        '--hidden-import=win32con',
        '--hidden-import=win32api',
        '--hidden-import=psutil',
        '--hidden-import=PIL',
        '--hidden-import=pyautogui',
        '--hidden-import=requests',
        '--name=JFS_SIEM_Agent_Enhanced',
        'jfs_agent_enhanced.py'
    ]
    
    print("\nBuilding EXE...")
    print(f"Command: {' '.join(build_cmd)}\n")
    
    result = subprocess.run(build_cmd, cwd='d:\\xamp\\htdocs\\SIEM\\collectors')
    
    if result.returncode == 0:
        print("\n" + "=" * 70)
        print("✓ BUILD SUCCESSFUL!")
        print("=" * 70)
        print("\nEXE Location:")
        print("d:\\xamp\\htdocs\\SIEM\\collectors\\dist\\JFS_SIEM_Agent_Enhanced.exe")
        print("\nFeatures:")
        print("✓ Windows Security Events")
        print("✓ Windows System Events")
        print("✓ Windows Application Events")
        print("✓ Process Execution Detection")
        print("✓ Network Connection Monitoring")
        print("✓ Service Status Changes")
        print("✓ User Account Changes")
        print("✓ Firewall Status")
        print("✓ Disk Space Alerts")
        print("✓ Memory Usage Alerts")
        print("✓ Remote Control (screenshots, keyboard, mouse, etc.)")
        print("✓ Windows Service Installation")
        print("=" * 70)
    else:
        print("\n" + "=" * 70)
        print("✗ BUILD FAILED")
        print("=" * 70)
        sys.exit(1)

if __name__ == '__main__':
    build_exe()
