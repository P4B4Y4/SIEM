#!/usr/bin/env python3
"""
Build script for JFS SIEM Agent v7 Stable
"""

import PyInstaller.main
import os
import sys

def build_agent():
    """Build the agent EXE"""
    
    # PyInstaller arguments
    args = [
        'jfs_agent_v7_stable.py',
        '--onefile',
        '--console',
        '--name=JFS_SIEM_Agent_v7_stable',
        '--distpath=dist',
        '--buildpath=build',
        '--specpath=.',
        '--noupx',  # Don't use UPX compression
        '--windowed=False',
        '--add-data=.;.',
        '--hidden-import=requests',
        '--hidden-import=psutil',
        '--hidden-import=PIL',
        '--collect-all=requests',
    ]
    
    print("Building JFS SIEM Agent v7 Stable...")
    print(f"Arguments: {args}")
    
    try:
        PyInstaller.main.run(args)
        print("\n✓ Build completed successfully!")
        
        # Check file size
        exe_path = 'dist/JFS_SIEM_Agent_v7_stable.exe'
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"✓ EXE created: {exe_path}")
            print(f"✓ Size: {size_mb:.2f} MB")
        else:
            print("ERROR: EXE not found after build")
            return False
        
        return True
    except Exception as e:
        print(f"ERROR: Build failed: {str(e)}")
        return False

if __name__ == '__main__':
    os.chdir(r'd:\xamp\htdocs\SIEM\collectors')
    success = build_agent()
    sys.exit(0 if success else 1)
