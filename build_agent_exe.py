#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JFS SIEM - Agent EXE Builder
Builds standalone JFS_SIEM_Agent_GUI.exe in the SIEM folder
No external dependencies needed - single file deployment
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

def build_agent_exe():
    """Build standalone agent GUI EXE"""
    
    script_dir = Path(__file__).parent
    agent_script = script_dir / "agent_gui_standalone.py"
    dist_dir = script_dir / "dist"
    build_dir = script_dir / "build"
    
    print("="*70)
    print("JFS SIEM - Agent EXE Builder")
    print("="*70)
    
    # Check if agent script exists
    if not agent_script.exists():
        print(f"\nERROR: {agent_script} not found!")
        print("\nPlease create agent_gui_standalone.py in the SIEM folder first.")
        return False
    
    print(f"\nAgent script found: {agent_script}")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"PyInstaller installed: {PyInstaller.__version__}")
    except ImportError:
        print("\nInstalling PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Clean previous builds
    print("\nCleaning previous builds...")
    if build_dir.exists():
        try:
            shutil.rmtree(build_dir, ignore_errors=True)
            print(f"Removed: {build_dir}")
        except:
            print(f"Could not remove: {build_dir}")
    
    if dist_dir.exists():
        try:
            shutil.rmtree(dist_dir, ignore_errors=True)
            print(f"Removed: {dist_dir}")
        except:
            print(f"Could not remove: {dist_dir}")
    
    # Build command
    print("\nBuilding standalone EXE...")
    print("-" * 70)
    
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--onefile",                          # Single EXE file
        "--windowed",                         # No console window
        "--name", "JFS_SIEM_Agent_GUI",      # EXE name
        "--distpath", str(dist_dir),
        "--workpath", str(build_dir),
        "--specpath", str(script_dir),
        str(agent_script)
    ]
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print("-" * 70)
        print("Build completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        return False
    
    # Check if EXE was created
    exe_path = dist_dir / "JFS_SIEM_Agent_GUI.exe"
    if exe_path.exists():
        exe_size = exe_path.stat().st_size / (1024 * 1024)  # Size in MB
        print(f"\nEXE created successfully!")
        print(f"  Location: {exe_path}")
        print(f"  Size: {exe_size:.1f} MB")
        
        print("\n" + "="*70)
        print("BUILD COMPLETE!")
        print("="*70)
        print(f"\nReady to deploy: {exe_path}")
        print("\nTo use:")
        print("1. Copy JFS_SIEM_Agent_GUI.exe to target PC")
        print("2. Double-click to run")
        print("3. Click 'Install Service'")
        print("4. Click 'Start Service'")
        print("5. Done! Service runs continuously")
        print("\n" + "="*70)
        
        return True
    else:
        print(f"ERROR: EXE not found at: {exe_path}")
        return False

if __name__ == "__main__":
    success = build_agent_exe()
    sys.exit(0 if success else 1)
