#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test if jfs_agent_service main works"""

print("TEST: Starting main test")

try:
    print("1. Importing jfs_agent_service...")
    from jfs_agent_service import handle_command_line
    print("   OK")
    
    print("2. Calling handle_command_line with no args...")
    import sys
    sys.argv = ['jfs_agent_service.py']  # Simulate running with no arguments
    print(f"   sys.argv = {sys.argv}")
    
    print("3. Calling handle_command_line...")
    handle_command_line(sys.argv)
    print("   OK - handle_command_line returned")
    
except Exception as e:
    print(f"\nERROR: {e}")
    import traceback
    traceback.print_exc()
