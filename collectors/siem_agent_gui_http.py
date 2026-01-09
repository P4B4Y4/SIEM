#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM HTTP Agent GUI - Modern Windows Style
"""

import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json
import threading
import socket
import sys
from datetime import datetime

try:
    import win32evtlog
    import win32con
except ImportError:
    print("ERROR: pywin32 not installed")
    sys.exit(1)

# JFS ICT Services Colors
JFS_BLUE = "#0066cc"
JFS_BLUE_LIGHT = "#3385dd"
JFS_BLUE_DARK = "#004499"
LIGHT_BG = "#f5f5f5"
LIGHT_SURFACE = "#ffffff"
SUCCESS_GREEN = "#10b981"
ERROR_RED = "#ef4444"
LIGHT_TEXT_PRIMARY = "#1f1f1f"

class SIEMAgentGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS ICT Services - SIEM Agent")
        self.root.geometry("700x600")
        self.root.configure(bg=LIGHT_BG)
        
        self.agent_running = False
        self.agent_thread = None
        self.events_sent = 0
        
        # Variables
        self.server_ip = tk.StringVar(value="192.168.1.52")
        self.server_port = tk.StringVar(value="80")
        self.pc_name = tk.StringVar(value=socket.gethostname())
        self.status_text = tk.StringVar(value="Ready to start")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup UI"""
        # Header
        header = tk.Frame(self.root, bg=JFS_BLUE, height=80)
        header.pack(fill=tk.X)
        
        title = tk.Label(header, text="JFS ICT Services", font=("Arial", 20, "bold"), 
                        bg=JFS_BLUE, fg="white")
        title.pack(pady=5)
        
        subtitle = tk.Label(header, text="SIEM Agent - Real-time Windows Event Collection", 
                           font=("Arial", 10), bg=JFS_BLUE, fg="white")
        subtitle.pack(pady=(0, 10))
        
        # Main content
        content = tk.Frame(self.root, bg=LIGHT_BG)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Configuration section
        config_label = tk.Label(content, text="Configuration", font=("Arial", 12, "bold"),
                               bg=LIGHT_BG, fg=LIGHT_TEXT_PRIMARY)
        config_label.pack(anchor=tk.W, pady=(0, 10))
        
        config_frame = tk.Frame(content, bg=LIGHT_SURFACE, relief=tk.FLAT, bd=1)
        config_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Server IP
        tk.Label(config_frame, text="Server IP:", bg=LIGHT_SURFACE).pack(anchor=tk.W, padx=10, pady=(10, 0))
        tk.Entry(config_frame, textvariable=self.server_ip, width=40).pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # Port
        tk.Label(config_frame, text="Port:", bg=LIGHT_SURFACE).pack(anchor=tk.W, padx=10, pady=(0, 0))
        tk.Entry(config_frame, textvariable=self.server_port, width=40).pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # PC Name
        tk.Label(config_frame, text="PC Name:", bg=LIGHT_SURFACE).pack(anchor=tk.W, padx=10, pady=(0, 0))
        tk.Entry(config_frame, textvariable=self.pc_name, width=40).pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # Control section
        control_label = tk.Label(content, text="Control", font=("Arial", 12, "bold"),
                                bg=LIGHT_BG, fg=LIGHT_TEXT_PRIMARY)
        control_label.pack(anchor=tk.W, pady=(0, 10))
        
        button_frame = tk.Frame(content, bg=LIGHT_BG)
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.start_btn = tk.Button(button_frame, text="▶ Start Agent", command=self.start_agent,
                                   bg=JFS_BLUE, fg="white", font=("Arial", 10, "bold"),
                                   padx=20, pady=10)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = tk.Button(button_frame, text="⏹ Stop Agent", command=self.stop_agent,
                                  bg=ERROR_RED, fg="white", font=("Arial", 10, "bold"),
                                  padx=20, pady=10, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        test_btn = tk.Button(button_frame, text="🔧 Test Connection", command=self.test_connection,
                            bg=LIGHT_SURFACE, fg=LIGHT_TEXT_PRIMARY, font=("Arial", 10),
                            padx=20, pady=10, relief=tk.SOLID, bd=1)
        test_btn.pack(side=tk.LEFT)
        
        # Status section
        status_label = tk.Label(content, text="Status", font=("Arial", 12, "bold"),
                               bg=LIGHT_BG, fg=LIGHT_TEXT_PRIMARY)
        status_label.pack(anchor=tk.W, pady=(0, 10))
        
        status_frame = tk.Frame(content, bg=LIGHT_SURFACE, relief=tk.FLAT, bd=1)
        status_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status text
        self.status_label = tk.Label(status_frame, textvariable=self.status_text,
                                     bg=LIGHT_SURFACE, fg=LIGHT_TEXT_PRIMARY,
                                     font=("Arial", 10), wraplength=600, justify=tk.LEFT)
        self.status_label.pack(padx=10, pady=10, anchor=tk.W)
        
        # Events counter
        self.events_label = tk.Label(status_frame, text="Events Sent: 0",
                                     bg=LIGHT_SURFACE, fg=JFS_BLUE,
                                     font=("Arial", 14, "bold"))
        self.events_label.pack(padx=10, pady=10, anchor=tk.W)
    
    def test_connection(self):
        """Test connection to server"""
        try:
            url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/agent-collector.php"
            response = requests.post(url, json={"test": True}, timeout=5)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Connection to SIEM server successful!")
                self.status_text.set("✓ Connection test successful")
            else:
                messagebox.showerror("Error", f"Server returned: {response.status_code}")
                self.status_text.set("✗ Connection test failed")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            self.status_text.set(f"✗ Connection error: {str(e)[:50]}")
    
    def start_agent(self):
        """Start the agent"""
        if self.agent_running:
            messagebox.showwarning("Warning", "Agent is already running")
            return
        
        self.agent_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_text.set("Starting agent...")
        
        self.agent_thread = threading.Thread(target=self.agent_loop, daemon=True)
        self.agent_thread.start()
    
    def stop_agent(self):
        """Stop the agent"""
        self.agent_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_text.set("Agent stopped")
    
    def agent_loop(self):
        """Main agent loop"""
        try:
            self.status_text.set("Agent running - collecting events...")
            
            while self.agent_running:
                try:
                    # Collect events
                    sec_count = self.collect_security_events()
                    sys_count = self.collect_system_events()
                    app_count = self.collect_application_events()
                    
                    total = sec_count + sys_count + app_count
                    self.status_text.set(f"Last cycle: {total} events (Security: {sec_count}, System: {sys_count}, App: {app_count})")
                    self.events_label.config(text=f"Events Sent: {self.events_sent}")
                    
                except Exception as e:
                    self.status_text.set(f"Error: {str(e)[:50]}")
                
                # Wait 10 seconds
                for _ in range(100):
                    if not self.agent_running:
                        break
                    self.root.after(100)
        
        except Exception as e:
            self.status_text.set(f"Agent error: {str(e)[:50]}")
            self.agent_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
    
    def send_event(self, event_data):
        """Send event to server"""
        try:
            url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/agent-collector.php"
            response = requests.post(url, json=event_data, timeout=5)
            if response.status_code == 200:
                self.events_sent += 1
                return True
            return False
        except:
            return False
    
    def collect_security_events(self):
        """Collect Security events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 10 or not self.agent_running:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name.get(),
                        'timestamp': timestamp,
                        'log_type': 'Security',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'windows_event',
                        'severity': 'info',
                        'what_happened': f"Event {event_id}",
                        'computer': self.pc_name.get()
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except:
            return 0
    
    def collect_system_events(self):
        """Collect System events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 5 or not self.agent_running:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name.get(),
                        'timestamp': timestamp,
                        'log_type': 'System',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'system_event',
                        'severity': 'info',
                        'what_happened': f"System event {event_id}",
                        'computer': self.pc_name.get()
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except:
            return 0
    
    def collect_application_events(self):
        """Collect Application events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'Application')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 5 or not self.agent_running:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name.get(),
                        'timestamp': timestamp,
                        'log_type': 'Application',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'application_event',
                        'severity': 'info',
                        'what_happened': f"App event {event_id}",
                        'computer': self.pc_name.get()
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except:
            return 0

if __name__ == '__main__':
    root = tk.Tk()
    app = SIEMAgentGUI(root)
    root.mainloop()
