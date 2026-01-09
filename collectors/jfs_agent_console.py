#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
JFS SIEM Agent - Console Only Version (No GUI)
"""
import sys
import os

print("="*70)
print("JFS SIEM Agent - Console Version")
print("="*70)
print(f"Python: {sys.version}")
print(f"Working dir: {os.getcwd()}")
print(f"Script dir: {os.path.dirname(__file__)}")

try:
    import json
    import socket
    import threading
    import time
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import win32evtlog
    import win32con
    
    print("\n✓ All imports successful!")
    
    class JFSAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "JFSSIEMAgent"
        _svc_display_name_ = "JFS SIEM Agent Service"
        
        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.is_alive = True
            
        def SvcStop(self):
            self.is_alive = False
            try:
                win32event.SetEvent(self.hWaitStop)
            except:
                pass
                
        def SvcDoRun(self):
            print("Service running")
            while self.is_alive:
                try:
                    rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 5000)
                    if rc == 0:
                        break
                except:
                    time.sleep(1)
    
    print("\n" + "="*70)
    print("MENU:")
    print("="*70)
    print("1. Install Service")
    print("2. Start Service")
    print("3. Stop Service")
    print("4. Remove Service")
    print("5. Exit")
    print("="*70)
    
    if len(sys.argv) > 1:
        print(f"\nCommand line argument: {sys.argv[1]}")
        win32serviceutil.HandleCommandLine(JFSAgentService)
    else:
        print("\nNo arguments provided. Service is ready.")
        print("Run with: install, start, stop, or remove")
        print("\nPress Enter to exit...")
        input()

except Exception as e:
    print(f"\n✗ ERROR: {e}")
    import traceback
    traceback.print_exc()
    print("\nPress Enter to exit...")
    input()
    sys.exit(1)
