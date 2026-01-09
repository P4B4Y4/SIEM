#!/usr/bin/env python3
"""
JFS SIEM Agent v6 - With Real Features
Wrapper to run jfs_agent_enhanced.py with real implementations
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the enhanced agent
if __name__ == '__main__':
    try:
        from jfs_agent_enhanced import JFSSIEMAgentComprehensive
        import tkinter as tk
        
        root = tk.Tk()
        app = JFSSIEMAgentComprehensive(root)
        root.mainloop()
    except ImportError as e:
        print(f"Error: Missing dependency: {e}")
        print("Please install required packages:")
        print("pip install tkinter requests psutil pillow pyautogui pywin32")
        sys.exit(1)
    except Exception as e:
        print(f"Error running agent: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
