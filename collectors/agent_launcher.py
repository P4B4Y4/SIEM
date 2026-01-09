#!/usr/bin/env python3
import sys
import os
import socket
import requests
import json
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jfs_agent_enhanced import JFSSIEMAgentComprehensive
import tkinter as tk

def register_agent(collector_ip, collector_port):
    """Register agent with the SIEM collector"""
    try:
        hostname = socket.gethostname()
        agent_id = f"agent-{hostname.lower()}"
        
        # Get local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"
        
        # Register with collector
        url = f"http://{collector_ip}:{collector_port}/SIEM/api/register-agent.php"
        payload = {
            'agent_id': agent_id,
            'agent_name': hostname,
            'agent_ip': local_ip,
            'hostname': hostname
        }
        
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"[✓] Agent registered: {agent_id}")
            return True
    except Exception as e:
        print(f"[!] Registration failed: {str(e)}")
    return False

if __name__ == '__main__':
    root = tk.Tk()
    app = JFSSIEMAgentComprehensive(root)
    
    # Register agent in background thread
    def register_on_startup():
        try:
            collector_ip = app.server_ip.get() if hasattr(app, 'server_ip') else "127.0.0.1"
            collector_port = app.server_port.get() if hasattr(app, 'server_port') else 9999
            register_agent(collector_ip, collector_port)
        except:
            pass
    
    threading.Thread(target=register_on_startup, daemon=True).start()
    root.mainloop()
