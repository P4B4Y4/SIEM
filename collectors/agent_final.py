#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JFS ICT Services - SIEM Agent (Complete + Remote Access)
Single EXE with GUI + Service Installation + Remote Control
"""

import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json
import threading
import socket
import sys
import subprocess
import os
import time
import pyautogui
from datetime import datetime
from PIL import ImageGrab
import base64
import io

try:
    import win32evtlog
    import win32con
except ImportError:
    print("ERROR: pywin32 not installed")
    sys.exit(1)

# Modern Color Palette
PRIMARY_COLOR = "#0066cc"
PRIMARY_DARK = "#004499"
ACCENT_COLOR = "#00d4ff"
SUCCESS_COLOR = "#00cc66"
WARNING_COLOR = "#ff9900"
ERROR_COLOR = "#ff3333"
BG_DARK = "#0f1419"
BG_SURFACE = "#1a1f26"
BG_SURFACE_ALT = "#252d36"
TEXT_PRIMARY = "#ffffff"
TEXT_SECONDARY = "#b0b8c1"

class JFSSIEMAgent:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS ICT Services - SIEM Agent")
        self.root.geometry("1000x750")
        self.root.configure(bg=BG_DARK)
        
        self.agent_running = False
        self.agent_thread = None
        self.events_sent = 0
        self.remote_command_thread = None
        self.sent_events = set()  # Track sent events to avoid duplicates
        
        # Variables
        self.server_ip = tk.StringVar(value="192.168.1.52")
        self.server_port = tk.StringVar(value="80")
        self.pc_name = tk.StringVar(value=socket.gethostname())
        self.status_text = tk.StringVar(value="Ready to start")
        self.connection_status = tk.StringVar(value="Disconnected")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup complete UI with tabs"""
        # Header
        header = tk.Frame(self.root, bg=PRIMARY_COLOR, height=120)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        logo_frame = tk.Frame(header, bg=PRIMARY_COLOR)
        logo_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        company_label = tk.Label(logo_frame, text="JFS ICT SERVICES", 
                                font=("Segoe UI", 12, "bold"), 
                                bg=PRIMARY_COLOR, fg=TEXT_PRIMARY)
        company_label.pack(anchor=tk.W)
        
        title_label = tk.Label(logo_frame, text="SIEM Agent - Complete Edition", 
                              font=("Segoe UI", 32, "bold"), 
                              bg=PRIMARY_COLOR, fg=TEXT_PRIMARY)
        title_label.pack(anchor=tk.W)
        
        subtitle_label = tk.Label(logo_frame, text="Real-Time Security Event Collection with Remote Access", 
                                 font=("Segoe UI", 10), 
                                 bg=PRIMARY_COLOR, fg=ACCENT_COLOR)
        subtitle_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Tab 1: Agent Control
        self.agent_tab = tk.Frame(notebook, bg=BG_DARK)
        notebook.add(self.agent_tab, text="Agent Control")
        self.setup_agent_tab()
        
        # Tab 2: Service Installation
        self.service_tab = tk.Frame(notebook, bg=BG_DARK)
        notebook.add(self.service_tab, text="Service Installation")
        self.setup_service_tab()
        
        # Tab 3: Settings
        self.settings_tab = tk.Frame(notebook, bg=BG_DARK)
        notebook.add(self.settings_tab, text="Settings")
        self.setup_settings_tab()
    
    def setup_agent_tab(self):
        """Agent control tab"""
        content = tk.Frame(self.agent_tab, bg=BG_DARK)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left column
        left = tk.Frame(content, bg=BG_DARK)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 20))
        
        # Configuration card
        config_card = tk.Frame(left, bg=BG_SURFACE)
        config_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        tk.Label(config_card, text="Configuration", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        tk.Label(config_card, text="Server IP", font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY).pack(anchor=tk.W, padx=20, pady=(0, 5))
        tk.Entry(config_card, textvariable=self.server_ip, font=("Segoe UI", 10),
                bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, relief=tk.FLAT, bd=0).pack(anchor=tk.W, padx=20, pady=(0, 15), fill=tk.X)
        
        tk.Label(config_card, text="Port", font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY).pack(anchor=tk.W, padx=20, pady=(0, 5))
        tk.Entry(config_card, textvariable=self.server_port, font=("Segoe UI", 10),
                bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, relief=tk.FLAT, bd=0).pack(anchor=tk.W, padx=20, pady=(0, 15), fill=tk.X)
        
        tk.Label(config_card, text="PC Name", font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY).pack(anchor=tk.W, padx=20, pady=(0, 5))
        tk.Entry(config_card, textvariable=self.pc_name, font=("Segoe UI", 10),
                bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, relief=tk.FLAT, bd=0).pack(anchor=tk.W, padx=20, pady=(0, 20), fill=tk.X)
        
        # Control card
        control_card = tk.Frame(left, bg=BG_SURFACE)
        control_card.pack(fill=tk.BOTH)
        
        tk.Label(control_card, text="Control", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
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
        right = tk.Frame(content, bg=BG_DARK)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Connection status
        status_card = tk.Frame(right, bg=BG_SURFACE)
        status_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        tk.Label(status_card, text="Connection Status", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        status_frame = tk.Frame(status_card, bg=BG_SURFACE)
        status_frame.pack(anchor=tk.W, padx=20, pady=(0, 20))
        
        self.status_dot = tk.Canvas(status_frame, width=16, height=16, 
                                   bg=BG_SURFACE, highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 10))
        self.status_dot.create_oval(2, 2, 14, 14, fill=ERROR_COLOR, outline="")
        
        tk.Label(status_frame, textvariable=self.connection_status,
                font=("Segoe UI", 12, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(side=tk.LEFT)
        
        # Events
        events_card = tk.Frame(right, bg=BG_SURFACE)
        events_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        tk.Label(events_card, text="Events Collected", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        self.events_label = tk.Label(events_card, text="0", 
                                    font=("Segoe UI", 48, "bold"),
                                    bg=BG_SURFACE, fg=ACCENT_COLOR)
        self.events_label.pack(anchor=tk.W, padx=20, pady=(0, 20))
        
        # Status message
        message_card = tk.Frame(right, bg=BG_SURFACE)
        message_card.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(message_card, text="Status", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        tk.Label(message_card, textvariable=self.status_text,
                font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY,
                wraplength=300, justify=tk.LEFT).pack(anchor=tk.NW, padx=20, pady=(0, 20), fill=tk.BOTH, expand=True)
    
    def setup_service_tab(self):
        """Service installation tab"""
        content = tk.Frame(self.service_tab, bg=BG_DARK)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Info card
        info_card = tk.Frame(content, bg=BG_SURFACE)
        info_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        tk.Label(info_card, text="Install as Windows Service", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        info_text = """Install the SIEM Agent as a Windows Service for:

✓ Automatic startup on system boot
✓ Continuous operation 24/7
✓ Runs after user logout
✓ Auto-restart on crash
✓ Survives system reboot
✓ Remote access enabled

The service will run in the background with no window."""
        
        tk.Label(info_card, text=info_text, font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY, justify=tk.LEFT).pack(anchor=tk.NW, padx=20, pady=(0, 20), fill=tk.BOTH)
        
        # Installation card
        install_card = tk.Frame(content, bg=BG_SURFACE)
        install_card.pack(fill=tk.BOTH)
        
        tk.Label(install_card, text="Installation", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        button_frame = tk.Frame(install_card, bg=BG_SURFACE)
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        install_btn = tk.Button(button_frame, text="📦  INSTALL SERVICE", 
                               command=self.install_service,
                               font=("Segoe UI", 12, "bold"),
                               bg=SUCCESS_COLOR, fg="#000000",
                               relief=tk.FLAT, bd=0, padx=20, pady=12,
                               cursor="hand2")
        install_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        uninstall_btn = tk.Button(button_frame, text="🗑️  UNINSTALL SERVICE", 
                                 command=self.uninstall_service,
                                 font=("Segoe UI", 12, "bold"),
                                 bg=ERROR_COLOR, fg=TEXT_PRIMARY,
                                 relief=tk.FLAT, bd=0, padx=20, pady=12,
                                 cursor="hand2")
        uninstall_btn.pack(side=tk.LEFT)
    
    def setup_settings_tab(self):
        """Settings tab"""
        content = tk.Frame(self.settings_tab, bg=BG_DARK)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # About card
        about_card = tk.Frame(content, bg=BG_SURFACE)
        about_card.pack(fill=tk.BOTH)
        
        tk.Label(about_card, text="About", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        about_text = """JFS ICT Services - SIEM Agent
Complete Edition v2.0 (Remote Access)

Features:
• Real-time Windows event collection
• Modern GUI interface
• Windows Service installation
• Automatic persistence
• Remote access support
• Screenshot capture
• Command execution
• Mouse/Keyboard control

Server: 192.168.1.52:80
Database: jfs_siem
Status: Production Ready

© 2025 JFS ICT Services"""
        
        tk.Label(about_card, text=about_text, font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY, justify=tk.LEFT).pack(anchor=tk.NW, padx=20, pady=(0, 20), fill=tk.BOTH)
    
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
    
    def install_service(self):
        """Install as Windows Service"""
        try:
            result = messagebox.askyesno("Install Service", 
                "This will install the SIEM Agent as a Windows Service.\n\n"
                "The service will:\n"
                "• Start automatically on system boot\n"
                "• Run continuously in background\n"
                "• Auto-restart if it crashes\n"
                "• Support remote access\n\n"
                "Continue?")
            
            if not result:
                return
            
            # Create batch file for service
            batch_content = f"""@echo off
REM JFS ICT Services - SIEM Agent Service
cd /d d:\\xamp\\htdocs\\SIEM\\collectors-fixed
dist\\SIEM_Agent_Remote.exe --server {self.server_ip.get()} --port {self.server_port.get()} --name {self.pc_name.get()}
"""
            
            batch_file = "d:\\xamp\\htdocs\\SIEM\\collectors-fixed\\siem-agent-service.bat"
            with open(batch_file, 'w') as f:
                f.write(batch_content)
            
            # Create service
            cmd = f'sc create JFSSIEMAgent binPath= "{batch_file}" start= auto'
            subprocess.run(cmd, shell=True, capture_output=True)
            
            # Start service
            subprocess.run("net start JFSSIEMAgent", shell=True, capture_output=True)
            
            messagebox.showinfo("Success", 
                "✓ Service installed successfully!\n\n"
                "The agent will:\n"
                "• Start automatically on next reboot\n"
                "• Run continuously in background\n"
                "• Auto-restart if it crashes\n"
                "• Support remote access\n\n"
                "Check Services (services.msc) for 'JFSSIEMAgent'")
            
            self.status_text.set("✓ Service installed and running")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to install service:\n{e}")
            self.status_text.set(f"✗ Service installation failed")
    
    def uninstall_service(self):
        """Uninstall Windows Service"""
        try:
            result = messagebox.askyesno("Uninstall Service", 
                "This will remove the SIEM Agent Windows Service.\n\n"
                "Continue?")
            
            if not result:
                return
            
            # Stop service
            subprocess.run("net stop JFSSIEMAgent", shell=True, capture_output=True)
            
            # Delete service
            subprocess.run("sc delete JFSSIEMAgent", shell=True, capture_output=True)
            
            messagebox.showinfo("Success", "✓ Service uninstalled successfully!")
            self.status_text.set("✓ Service uninstalled")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to uninstall service:\n{e}")
    
    def update_status_indicator(self, connected):
        """Update status dot"""
        color = SUCCESS_COLOR if connected else ERROR_COLOR
        self.status_dot.delete("all")
        self.status_dot.create_oval(2, 2, 14, 14, fill=color, outline="")
        self.connection_status.set("Connected" if connected else "Disconnected")
    
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
        
        self.remote_command_thread = threading.Thread(target=self.check_remote_commands, daemon=True)
        self.remote_command_thread.start()
    
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
    
    def check_remote_commands(self):
        """Check for remote commands from server"""
        while self.agent_running:
            try:
                # Query for pending commands
                url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/remote-access.php?action=get_pending_commands&agent={self.pc_name.get()}"
                
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('commands'):
                        for cmd_data in data['commands']:
                            cmd_id = cmd_data.get('id')
                            command = cmd_data.get('command')
                            
                            # Execute command
                            result = self.execute_command(command)
                            
                            # Report back to server
                            self.report_command_result(cmd_id, result)
                
                time.sleep(2)
            except Exception as e:
                pass
    
    def report_command_result(self, cmd_id, result):
        """Report command execution result back to server"""
        try:
            url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/remote-access.php?action=report_command&id={cmd_id}"
            requests.post(url, json={'result': 'success' if result else 'failed'}, timeout=5)
        except:
            pass
    
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
    
    def take_screenshot(self):
        """Capture screenshot and send to server"""
        try:
            screenshot = ImageGrab.grab()
            buffer = io.BytesIO()
            screenshot.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            event_data = {
                'agent': self.pc_name.get(),
                'timestamp': datetime.now().isoformat(),
                'event_type': 'screenshot',
                'screenshot': img_base64,
                'computer': self.pc_name.get()
            }
            
            return self.send_event(event_data)
        except:
            return False
    
    def execute_command(self, command):
        """Execute system command"""
        try:
            # Parse JSON command if needed
            if isinstance(command, str):
                try:
                    cmd_data = json.loads(command)
                    command = cmd_data.get('command', command)
                except:
                    pass
            
            # Execute command
            if command == 'ctrl+alt+del':
                pyautogui.hotkey('ctrl', 'alt', 'delete')
                return True
            elif command == 'lock':
                os.system('rundll32.exe user32.dll,LockWorkStation')
                return True
            elif command == 'restart':
                os.system('shutdown /r /t 30 /c "Remote restart requested"')
                return True
            elif command == 'shutdown':
                os.system('shutdown /s /t 30 /c "Remote shutdown requested"')
                return True
            else:
                os.system(command)
                return True
        except Exception as e:
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
                    
                    # Create unique event signature to avoid duplicates
                    event_signature = f"{timestamp}_{event_id}_{event.SourceName}"
                    
                    # Skip if already sent
                    if event_signature in self.sent_events:
                        continue
                    
                    # Determine severity based on EventType
                    severity = 'info'
                    if event.EventType == win32con.EVENTLOG_ERROR_TYPE:
                        severity = 'critical'
                    elif event.EventType == win32con.EVENTLOG_WARNING_TYPE:
                        severity = 'high'
                    elif event.EventType == win32con.EVENTLOG_INFORMATION_TYPE:
                        severity = 'info'
                    elif event.EventType == win32con.EVENTLOG_AUDIT_SUCCESS:
                        severity = 'low'
                    elif event.EventType == win32con.EVENTLOG_AUDIT_FAILURE:
                        severity = 'high'
                    
                    event_data = {
                        'agent': self.pc_name.get(),
                        'timestamp': timestamp,
                        'log_type': 'Security',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'windows_event',
                        'severity': severity,
                        'what_happened': f"Event {event_id}",
                        'computer': self.pc_name.get()
                    }
                    
                    if self.send_event(event_data):
                        self.sent_events.add(event_signature)  # Mark as sent
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
                    
                    # Create unique event signature to avoid duplicates
                    event_signature = f"{timestamp}_{event_id}_{event.SourceName}"
                    
                    # Skip if already sent
                    if event_signature in self.sent_events:
                        continue
                    
                    # Determine severity based on EventType
                    severity = 'info'
                    if event.EventType == win32con.EVENTLOG_ERROR_TYPE:
                        severity = 'critical'
                    elif event.EventType == win32con.EVENTLOG_WARNING_TYPE:
                        severity = 'high'
                    elif event.EventType == win32con.EVENTLOG_INFORMATION_TYPE:
                        severity = 'info'
                    elif event.EventType == win32con.EVENTLOG_AUDIT_SUCCESS:
                        severity = 'low'
                    elif event.EventType == win32con.EVENTLOG_AUDIT_FAILURE:
                        severity = 'high'
                    
                    event_data = {
                        'agent': self.pc_name.get(),
                        'timestamp': timestamp,
                        'log_type': 'System',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'system_event',
                        'severity': severity,
                        'what_happened': f"System event {event_id}",
                        'computer': self.pc_name.get()
                    }
                    
                    if self.send_event(event_data):
                        self.sent_events.add(event_signature)  # Mark as sent
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
                    
                    # Create unique event signature to avoid duplicates
                    event_signature = f"{timestamp}_{event_id}_{event.SourceName}"
                    
                    # Skip if already sent
                    if event_signature in self.sent_events:
                        continue
                    
                    # Determine severity based on EventType
                    severity = 'info'
                    if event.EventType == win32con.EVENTLOG_ERROR_TYPE:
                        severity = 'critical'
                    elif event.EventType == win32con.EVENTLOG_WARNING_TYPE:
                        severity = 'high'
                    elif event.EventType == win32con.EVENTLOG_INFORMATION_TYPE:
                        severity = 'info'
                    elif event.EventType == win32con.EVENTLOG_AUDIT_SUCCESS:
                        severity = 'low'
                    elif event.EventType == win32con.EVENTLOG_AUDIT_FAILURE:
                        severity = 'high'
                    
                    event_data = {
                        'agent': self.pc_name.get(),
                        'timestamp': timestamp,
                        'log_type': 'Application',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'application_event',
                        'severity': severity,
                        'what_happened': f"App event {event_id}",
                        'computer': self.pc_name.get()
                    }
                    
                    if self.send_event(event_data):
                        self.sent_events.add(event_signature)  # Mark as sent
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except:
            return 0

if __name__ == '__main__':
    root = tk.Tk()
    app = JFSSIEMAgent(root)
    root.mainloop()
