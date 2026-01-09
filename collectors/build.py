#!/usr/bin/env python
import subprocess
import sys
from pathlib import Path

script_dir = Path(__file__).parent
agent = script_dir / "agent_final.py"
dist = script_dir / "dist"
build = script_dir / "build"

print("Building...")

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile",
    "--console",
    "--name", "JFS_SIEM_Agent",
    "--hidden-import=win32serviceutil",
    "--hidden-import=win32service",
    "--hidden-import=win32event",
    "--hidden-import=servicemanager",
    "--distpath", str(dist),
    "--workpath", str(build),
    str(agent)
]

subprocess.run(cmd, check=True)

exe = dist / "JFS_SIEM_Agent.exe"
if exe.exists():
    print(f"Built: {exe}")
else:
    print("Build failed")
    sys.exit(1)
