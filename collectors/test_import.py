#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test if jfs_agent_service imports correctly"""

print("=" * 70)
print("TEST: Starting import test")
print("=" * 70)

try:
    print("\n1. Importing sys...")
    import sys
    print("   OK")
    
    print("2. Importing os...")
    import os
    print("   OK")
    
    print("3. Importing json...")
    import json
    print("   OK")
    
    print("4. Importing socket...")
    import socket
    print("   OK")
    
    print("5. Importing time...")
    import time
    print("   OK")
    
    print("6. Importing logging...")
    import logging
    print("   OK")
    
    print("7. Importing threading...")
    import threading
    print("   OK")
    
    print("8. Importing tkinter...")
    import tkinter as tk
    print("   OK")
    
    print("9. Importing tkinter.ttk...")
    from tkinter import ttk, messagebox
    print("   OK")
    
    print("10. Importing win32serviceutil...")
    import win32serviceutil
    print("   OK")
    
    print("11. Importing win32service...")
    import win32service
    print("   OK")
    
    print("12. Importing win32event...")
    import win32event
    print("   OK")
    
    print("13. Importing servicemanager...")
    import servicemanager
    print("   OK")
    
    print("14. Importing win32evtlog...")
    import win32evtlog
    print("   OK")
    
    print("15. Importing win32con...")
    import win32con
    print("   OK")
    
    print("16. Importing datetime...")
    from datetime import datetime
    print("   OK")
    
    print("\n" + "=" * 70)
    print("ALL IMPORTS SUCCESSFUL!")
    print("=" * 70)
    
    print("\nNow trying to import jfs_agent_service...")
    from jfs_agent_service import JFSAgentService
    print("SUCCESS: jfs_agent_service imported!")
    
except Exception as e:
    print(f"\nERROR: {e}")
    import traceback
    traceback.print_exc()
