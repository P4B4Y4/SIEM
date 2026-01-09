#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JFS ICT Services - SIEM Agent GUI (Modern Design)
Sleek, contemporary UI with gradient effects and smooth animations
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

# Modern Color Palette
PRIMARY_COLOR = "#0066cc"      # JFS Blue
PRIMARY_DARK = "#004499"       # Dark Blue
ACCENT_COLOR = "#00d4ff"       # Cyan
SUCCESS_COLOR = "#00cc66"      # Green
WARNING_COLOR = "#ff9900"      # Orange
ERROR_COLOR = "#ff3333"        # Red
BG_DARK = "#0f1419"            # Very dark background
BG_SURFACE = "#1a1f26"         # Surface color
BG_SURFACE_ALT = "#252d36"     # Alternative surface
TEXT_PRIMARY = "#ffffff"       # White text
TEXT_SECONDARY = "#b0b8c1"     # Gray text

class ModernSIEMGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS ICT Services - SIEM Agent")
        self.root.geometry("900x700")
        self.root.configure(bg=BG_DARK)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.agent_running = False
        self.agent_thread = None
        self.events_sent = 0
        
        # Variables
        self.server_ip = tk.StringVar(value="192.168.1.52")
        self.server_port = tk.StringVar(value="80")
        self.pc_name = tk.StringVar(value=socket.gethostname())
        self.status_text = tk.StringVar(value="Ready to start")
        self.connection_status = tk.StringVar(value="Disconnected")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup modern UI"""
        # Header with gradient effect
        header = tk.Frame(self.root, bg=PRIMARY_COLOR, height=120)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        # Company logo area
        logo_frame = tk.Frame(header, bg=PRIMARY_COLOR)
        logo_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        company_label = tk.Label(logo_frame, text="JFS ICT SERVICES", 
                                font=("Segoe UI", 12, "bold"), 
                                bg=PRIMARY_COLOR, fg=TEXT_PRIMARY)
        company_label.pack(anchor=tk.W)
        
        title_label = tk.Label(logo_frame, text="SIEM Agent", 
                              font=("Segoe UI", 32, "bold"), 
                              bg=PRIMARY_COLOR, fg=TEXT_PRIMARY)
        title_label.pack(anchor=tk.W)
        
        subtitle_label = tk.Label(logo_frame, text="Real-Time Security Event Collection", 
                                 font=("Segoe UI", 10), 
                                 bg=PRIMARY_COLOR, fg=ACCENT_COLOR)
        subtitle_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Main content
        content = tk.Frame(self.root, bg=BG_DARK)
        content.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Left column - Configuration
        left_column = tk.Frame(content, bg=BG_DARK)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 20))
        
        # Configuration card
        config_card = tk.Frame(left_column, bg=BG_SURFACE, relief=tk.FLAT)
        config_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        config_title = tk.Label(config_card, text="Configuration", 
                               font=("Segoe UI", 14, "bold"),
                               bg=BG_SURFACE, fg=TEXT_PRIMARY)
        config_title.pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        # Server IP
        tk.Label(config_card, text="Server IP", font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY).pack(anchor=tk.W, padx=20, pady=(0, 5))
        ip_entry = tk.Entry(config_card, textvariable=self.server_ip, 
                           font=("Segoe UI", 10), bg=BG_SURFACE_ALT, 
                           fg=TEXT_PRIMARY, relief=tk.FLAT, bd=0)
        ip_entry.pack(anchor=tk.W, padx=20, pady=(0, 15), fill=tk.X)
        
        # Port
        tk.Label(config_card, text="Port", font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY).pack(anchor=tk.W, padx=20, pady=(0, 5))
        port_entry = tk.Entry(config_card, textvariable=self.server_port, 
                             font=("Segoe UI", 10), bg=BG_SURFACE_ALT, 
                             fg=TEXT_PRIMARY, relief=tk.FLAT, bd=0)
        port_entry.pack(anchor=tk.W, padx=20, pady=(0, 15), fill=tk.X)
        
        # PC Name
        tk.Label(config_card, text="PC Name", font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY).pack(anchor=tk.W, padx=20, pady=(0, 5))
        name_entry = tk.Entry(config_card, textvariable=self.pc_name, 
                             font=("Segoe UI", 10), bg=BG_SURFACE_ALT, 
                             fg=TEXT_PRIMARY, relief=tk.FLAT, bd=0)
        name_entry.pack(anchor=tk.W, padx=20, pady=(0, 20), fill=tk.X)
        
        # Control card
        control_card = tk.Frame(left_column, bg=BG_SURFACE, relief=tk.FLAT)
        control_card.pack(fill=tk.BOTH)
        
        control_title = tk.Label(control_card, text="Control", 
                                font=("Segoe UI", 14, "bold"),
                                bg=BG_SURFACE, fg=TEXT_PRIMARY)
        control_title.pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        button_frame = tk.Frame(control_card, bg=BG_SURFACE)
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.start_btn = tk.Button(button_frame, text="▶  START AGENT", 
                                  command=self.start_agent,
                                  font=("Segoe UI", 11, "bold"),
                                  bg=PRIMARY_COLOR, fg=TEXT_PRIMARY,
                                  relief=tk.FLAT, bd=0, padx=20, pady=12,
                                  cursor="hand2")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = tk.Button(button_frame, text="⏹  STOP AGENT", 
                                 command=self.stop_agent,
                                 font=("Segoe UI", 11, "bold"),
                                 bg=ERROR_COLOR, fg=TEXT_PRIMARY,
                                 relief=tk.FLAT, bd=0, padx=20, pady=12,
                                 cursor="hand2", state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        test_btn = tk.Button(button_frame, text="🔧  TEST", 
                            command=self.test_connection,
                            font=("Segoe UI", 11, "bold"),
                            bg=BG_SURFACE_ALT, fg=ACCENT_COLOR,
                            relief=tk.FLAT, bd=0, padx=20, pady=12,
                            cursor="hand2")
        test_btn.pack(side=tk.LEFT)
        
        # Right column - Status
        right_column = tk.Frame(content, bg=BG_DARK)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Connection status card
        status_card = tk.Frame(right_column, bg=BG_SURFACE, relief=tk.FLAT)
        status_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        status_title = tk.Label(status_card, text="Connection Status", 
                               font=("Segoe UI", 14, "bold"),
                               bg=BG_SURFACE, fg=TEXT_PRIMARY)
        status_title.pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        # Status indicator
        status_frame = tk.Frame(status_card, bg=BG_SURFACE)
        status_frame.pack(anchor=tk.W, padx=20, pady=(0, 20))
        
        self.status_dot = tk.Canvas(status_frame, width=16, height=16, 
                                   bg=BG_SURFACE, highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 10))
        self.status_dot.create_oval(2, 2, 14, 14, fill=ERROR_COLOR, outline="")
        
        self.status_label = tk.Label(status_frame, textvariable=self.connection_status,
                                    font=("Segoe UI", 12, "bold"),
                                    bg=BG_SURFACE, fg=TEXT_PRIMARY)
        self.status_label.pack(side=tk.LEFT)
        
        # Events card
        events_card = tk.Frame(right_column, bg=BG_SURFACE, relief=tk.FLAT)
        events_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        events_title = tk.Label(events_card, text="Events Collected", 
                               font=("Segoe UI", 14, "bold"),
                               bg=BG_SURFACE, fg=TEXT_PRIMARY)
        events_title.pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        self.events_label = tk.Label(events_card, text="0", 
                                    font=("Segoe UI", 48, "bold"),
                                    bg=BG_SURFACE, fg=ACCENT_COLOR)
        self.events_label.pack(anchor=tk.W, padx=20, pady=(0, 20))
        
        # Status message card
        message_card = tk.Frame(right_column, bg=BG_SURFACE, relief=tk.FLAT)
        message_card.pack(fill=tk.BOTH, expand=True)
        
        message_title = tk.Label(message_card, text="Status", 
                                font=("Segoe UI", 14, "bold"),
                                bg=BG_SURFACE, fg=TEXT_PRIMARY)
        message_title.pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        self.message_label = tk.Label(message_card, textvariable=self.status_text,
                                     font=("Segoe UI", 10),
                                     bg=BG_SURFACE, fg=TEXT_SECONDARY,
                                     wraplength=300, justify=tk.LEFT)
        self.message_label.pack(anchor=tk.NW, padx=20, pady=(0, 20), fill=tk.BOTH, expand=True)
    
    def update_status_indicator(self, connected):
        """Update status dot color"""
        color = SUCCESS_COLOR if connected else ERROR_COLOR
        self.status_dot.delete("all")
        self.status_dot.create_oval(2, 2, 14, 14, fill=color, outline="")
        self.connection_status.set("Connected" if connected else "Disconnected")
    
    def test_connection(self):
        """Test connection"""
        try:
            url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/agent-collector.php"
            response = requests.post(url, json={"test": True}, timeout=5)
            if response.status_code == 200:
                messagebox.showinfo("Success", "✓ Connection successful!")
                self.status_text.set("✓ Connection test passed")
                self.update_status_indicator(True)
            else:
                messagebox.showerror("Error", f"✗ Server error: {response.status_code}")
                self.status_text.set("✗ Connection test failed")
                self.update_status_indicator(False)
        except Exception as e:
            messagebox.showerror("Error", f"✗ Connection failed: {e}")
            self.status_text.set(f"✗ Error: {str(e)[:40]}")
            self.update_status_indicator(False)
    
    def start_agent(self):
        """Start agent"""
        if self.agent_running:
            messagebox.showwarning("Warning", "Agent is already running")
            return
        
        self.agent_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_text.set("Agent running - collecting events...")
        self.update_status_indicator(True)
        
        self.agent_thread = threading.Thread(target=self.agent_loop, daemon=True)
        self.agent_thread.start()
    
    def stop_agent(self):
        """Stop agent"""
        self.agent_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_text.set("Agent stopped")
        self.update_status_indicator(False)
    
    def agent_loop(self):
        """Main agent loop"""
        try:
            while self.agent_running:
                try:
                    sec_count = self.collect_security_events()
                    sys_count = self.collect_system_events()
                    app_count = self.collect_application_events()
                    
                    total = sec_count + sys_count + app_count
                    self.status_text.set(f"Last cycle: {total} events (S:{sec_count} Sy:{sys_count} A:{app_count})")
                    self.events_label.config(text=str(self.events_sent))
                
                except Exception as e:
                    self.status_text.set(f"Error: {str(e)[:40]}")
                
                for _ in range(100):
                    if not self.agent_running:
                        break
                    self.root.after(100)
        
        except Exception as e:
            self.status_text.set(f"Agent error: {str(e)[:40]}")
            self.agent_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.update_status_indicator(False)
    
    def send_event(self, event_data):
        """Send event"""
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
    app = ModernSIEMGUI(root)
    root.mainloop()
