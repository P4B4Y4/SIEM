# -*- coding: utf-8 -*-
"""
JFS SIEM - Agent GUI (Modern Windows Style)
Fluent Design / Glass Morphism UI

REQUIREMENTS:
pip install tkinter (usually included with Python)
pip install pywin32
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import json
import threading
import subprocess
import sys
import os
from datetime import datetime

# Brand color
BRAND_NAVY = "#000080"
BRAND_NAVY_LIGHT = "#1a1a9e"
BRAND_NAVY_DARK = "#000066"

# Light mode colors
LIGHT_BG = "#f5f5f5"
LIGHT_SURFACE = "#ffffff"
LIGHT_SURFACE_HOVER = "#f0f0f0"
LIGHT_BORDER = "#e0e0e0"
LIGHT_TEXT_PRIMARY = "#1f1f1f"
LIGHT_TEXT_SECONDARY = "#666666"

# Accent colors
ACCENT_BLUE = "#0078d4"
SUCCESS_GREEN = "#10b981"
WARNING_ORANGE = "#f59e0b"
ERROR_RED = "#ef4444"

class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    def __init__(self, parent, text, command, variant="primary", width=120, height=36):
        super().__init__(parent, width=width, height=height, 
                        highlightthickness=0, bg=LIGHT_SURFACE)
        
        self.text = text
        self.command = command
        self.variant = variant
        self.width = width
        self.height = height
        self.is_hovered = False
        self.is_pressed = False
        self.is_disabled = False
        
        # Colors based on variant
        if variant == "primary":
            self.bg_normal = BRAND_NAVY
            self.bg_hover = BRAND_NAVY_LIGHT
            self.bg_pressed = BRAND_NAVY_DARK
            self.fg_color = "#ffffff"
            self.has_border = False
        else:  # secondary
            self.bg_normal = LIGHT_SURFACE
            self.bg_hover = LIGHT_SURFACE_HOVER
            self.bg_pressed = LIGHT_BORDER
            self.fg_color = LIGHT_TEXT_PRIMARY
            self.has_border = True
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_press)
        self.bind("<ButtonRelease-1>", self.on_release)
        
        self.draw()
    
    def draw(self):
        self.delete("all")
        
        # Determine current colors
        if self.is_disabled:
            bg = self.bg_normal
            fg = self.fg_color
            alpha = 128  # 50% opacity
        elif self.is_pressed:
            bg = self.bg_pressed
            fg = self.fg_color
            alpha = 255
        elif self.is_hovered:
            bg = self.bg_hover
            fg = self.fg_color
            alpha = 255
        else:
            bg = self.bg_normal
            fg = self.fg_color
            alpha = 255
        
        # Draw rounded rectangle background
        radius = 6
        self.create_rounded_rect(2, 2, self.width-2, self.height-2, 
                                radius, fill=bg, outline=LIGHT_BORDER if self.has_border else "")
        
        # Draw text
        self.create_text(self.width/2, self.height/2, text=self.text,
                        fill=fg, font=("Segoe UI", 10, "bold"))
    
    def create_rounded_rect(self, x1, y1, x2, y2, radius, **kwargs):
        points = [
            x1+radius, y1,
            x1+radius, y1,
            x2-radius, y1,
            x2-radius, y1,
            x2, y1,
            x2, y1+radius,
            x2, y1+radius,
            x2, y2-radius,
            x2, y2-radius,
            x2, y2,
            x2-radius, y2,
            x2-radius, y2,
            x1+radius, y2,
            x1+radius, y2,
            x1, y2,
            x1, y2-radius,
            x1, y2-radius,
            x1, y1+radius,
            x1, y1+radius,
            x1, y1
        ]
        return self.create_polygon(points, smooth=True, **kwargs)
    
    def on_enter(self, event):
        if not self.is_disabled:
            self.is_hovered = True
            self.draw()
    
    def on_leave(self, event):
        self.is_hovered = False
        self.is_pressed = False
        self.draw()
    
    def on_press(self, event):
        if not self.is_disabled:
            self.is_pressed = True
            self.draw()
    
    def on_release(self, event):
        if not self.is_disabled:
            self.is_pressed = False
            self.draw()
            if self.is_hovered and self.command:
                self.command()
    
    def set_state(self, state):
        """Set button state: 'normal' or 'disabled'"""
        self.is_disabled = (state == "disabled")
        self.draw()

class StatusIndicator(tk.Canvas):
    """Animated status indicator (Connected/Disconnected)"""
    def __init__(self, parent, status="disconnected"):
        super().__init__(parent, width=12, height=12, 
                        highlightthickness=0, bg=LIGHT_SURFACE)
        self.status = status
        self.draw()
    
    def draw(self):
        self.delete("all")
        color = SUCCESS_GREEN if self.status == "connected" else ERROR_RED
        self.create_oval(2, 2, 10, 10, fill=color, outline="")
    
    def set_status(self, status):
        self.status = status
        self.draw()

class ModernCard(tk.Frame):
    """Card container with shadow effect"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=LIGHT_SURFACE, relief=tk.FLAT, 
                        borderwidth=1, **kwargs)
        self.config(highlightbackground=LIGHT_BORDER, highlightthickness=1)

class JFSModernAgentGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent Manager")
        self.root.geometry("900x750")
        self.root.configure(bg=LIGHT_BG)
        
        # Remove default window decorations for custom look (optional)
        # self.root.overrideredirect(True)
        
        # Variables
        self.collector_ip = tk.StringVar(value="192.168.1.100")
        self.collector_port = tk.StringVar(value="9999")
        self.agent_name = tk.StringVar(value=socket.gethostname())
        self.status_text = tk.StringVar(value="Ready to start")
        self.connection_status = tk.StringVar(value="Disconnected")
        self.events_collected = tk.StringVar(value="0")
        
        self.agent_running = False
        self.agent_thread = None
        
        # Configure style
        self.setup_styles()
        self.setup_ui()
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure(".", 
                       background=LIGHT_SURFACE,
                       foreground=LIGHT_TEXT_PRIMARY,
                       fieldbackground=LIGHT_SURFACE)
        
        # Entry style
        style.configure("Modern.TEntry",
                       fieldbackground=LIGHT_SURFACE,
                       bordercolor=LIGHT_BORDER,
                       lightcolor=LIGHT_BORDER,
                       darkcolor=LIGHT_BORDER,
                       borderwidth=1,
                       relief=tk.FLAT)
        
        # Label style
        style.configure("Title.TLabel",
                       font=("Segoe UI", 22, "bold"),
                       background=LIGHT_SURFACE,
                       foreground=LIGHT_TEXT_PRIMARY)
        
        style.configure("Heading.TLabel",
                       font=("Segoe UI", 14, "bold"),
                       background=LIGHT_SURFACE,
                       foreground=LIGHT_TEXT_PRIMARY)
        
        style.configure("Body.TLabel",
                       font=("Segoe UI", 10),
                       background=LIGHT_SURFACE,
                       foreground=LIGHT_TEXT_PRIMARY)
        
        style.configure("Caption.TLabel",
                       font=("Segoe UI", 9),
                       background=LIGHT_SURFACE,
                       foreground=LIGHT_TEXT_SECONDARY)
        
        style.configure("Card.TFrame",
                       background=LIGHT_SURFACE,
                       relief=tk.FLAT)
    
    def setup_ui(self):
        """Setup the modern UI layout"""
        
        # Main container with padding
        main_container = tk.Frame(self.root, bg=LIGHT_BG)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # ===== TOP BAR =====
        top_bar = ModernCard(main_container)
        top_bar.pack(fill=tk.X, pady=(0, 16))
        
        top_content = tk.Frame(top_bar, bg=LIGHT_SURFACE)
        top_content.pack(fill=tk.X, padx=24, pady=16)
        
        # Title with icon
        title_frame = tk.Frame(top_content, bg=LIGHT_SURFACE)
        title_frame.pack(side=tk.LEFT)
        
        ttk.Label(title_frame, text="", font=("Segoe UI", 24)).pack(side=tk.LEFT, padx=(0, 12))
        title_label = ttk.Label(title_frame, text="JFS SIEM Agent Manager", 
                               style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        # Status indicator in top bar
        status_frame = tk.Frame(top_content, bg=LIGHT_SURFACE)
        status_frame.pack(side=tk.RIGHT)
        
        self.status_indicator = StatusIndicator(status_frame)
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 8))
        
        self.conn_status_label = ttk.Label(status_frame, 
                                           textvariable=self.connection_status,
                                           font=("Segoe UI", 10, "bold"),
                                           foreground=ERROR_RED)
        self.conn_status_label.pack(side=tk.LEFT)
        
        # ===== MAIN CONTENT AREA =====
        content_area = tk.Frame(main_container, bg=LIGHT_BG)
        content_area.pack(fill=tk.BOTH, expand=True)
        
        # Left column (Configuration)
        left_column = tk.Frame(content_area, bg=LIGHT_BG)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        
        # Configuration Card
        config_card = ModernCard(left_column)
        config_card.pack(fill=tk.X, pady=(0, 16))
        
        config_content = tk.Frame(config_card, bg=LIGHT_SURFACE)
        config_content.pack(fill=tk.X, padx=24, pady=20)
        
        ttk.Label(config_content, text="Configuration", 
                 style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 16))
        
        # IP Address
        self.create_input_field(config_content, "Collector IP Address", 
                               self.collector_ip, "e.g., 192.168.1.100")
        
        # Port
        self.create_input_field(config_content, "Port Number", 
                               self.collector_port, "default: 9999")
        
        # Agent Name
        self.create_input_field(config_content, "Agent Name", 
                               self.agent_name, "This computer''s identifier")
        
        # Control Card
        control_card = ModernCard(left_column)
        control_card.pack(fill=tk.X, pady=(0, 16))
        
        control_content = tk.Frame(control_card, bg=LIGHT_SURFACE)
        control_content.pack(fill=tk.X, padx=24, pady=20)
        
        ttk.Label(control_content, text="Control", 
                 style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 16))
        
        # Buttons
        button_frame = tk.Frame(control_content, bg=LIGHT_SURFACE)
        button_frame.pack(fill=tk.X, pady=(0, 12))
        
        self.start_btn = ModernButton(button_frame, " Start Agent", 
                                      self.start_agent, variant="primary", width=140)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.stop_btn = ModernButton(button_frame, " Stop Agent", 
                                     self.stop_agent, variant="secondary", width=140)
        self.stop_btn.set_state("disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        test_btn = ModernButton(button_frame, " Test Connection", 
                               self.test_connection, variant="secondary", width=150)
        test_btn.pack(side=tk.LEFT)
        
        # Service button
        service_btn = ModernButton(control_content, " Install as Windows Service", 
                                  self.install_service, variant="secondary", width=220, height=40)
        service_btn.pack(anchor=tk.W)
        
        # Right column (Status & Logs)
        right_column = tk.Frame(content_area, bg=LIGHT_BG)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))
        
        # Statistics Cards
        stats_row = tk.Frame(right_column, bg=LIGHT_BG)
        stats_row.pack(fill=tk.X, pady=(0, 16))
        
        # Events card
        events_card = ModernCard(stats_row)
        events_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        
        events_content = tk.Frame(events_card, bg=LIGHT_SURFACE)
        events_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        
        ttk.Label(events_content, text="Events Collected", 
                 style="Caption.TLabel").pack(anchor=tk.W)
        ttk.Label(events_content, textvariable=self.events_collected,
                 font=("Segoe UI", 28, "bold"),
                 foreground=BRAND_NAVY).pack(anchor=tk.W, pady=(4, 0))
        
        # Status card
        status_card = ModernCard(stats_row)
        status_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        status_content = tk.Frame(status_card, bg=LIGHT_SURFACE)
        status_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        
        ttk.Label(status_content, text="Current Status", 
                 style="Caption.TLabel").pack(anchor=tk.W)
        
        status_text_label = ttk.Label(status_content, textvariable=self.status_text,
                                      font=("Segoe UI", 11),
                                      foreground=LIGHT_TEXT_PRIMARY,
                                      wraplength=200)
        status_text_label.pack(anchor=tk.W, pady=(4, 0))
        
        # Activity Log Card
        log_card = ModernCard(right_column)
        log_card.pack(fill=tk.BOTH, expand=True)
        
        log_content = tk.Frame(log_card, bg=LIGHT_SURFACE)
        log_content.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)
        
        # Log header
        log_header = tk.Frame(log_content, bg=LIGHT_SURFACE)
        log_header.pack(fill=tk.X, pady=(0, 12))
        
        ttk.Label(log_header, text="Activity Log", 
                 style="Heading.TLabel").pack(side=tk.LEFT)
        
        clear_btn = ModernButton(log_header, "Clear", self.clear_log, 
                                variant="secondary", width=80, height=28)
        clear_btn.pack(side=tk.RIGHT)
        
        # Log text area with custom styling
        log_frame = tk.Frame(log_content, bg=LIGHT_SURFACE)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(log_frame, bg=LIGHT_SURFACE)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(log_frame, 
                               height=12,
                               bg=LIGHT_BG,
                               fg=LIGHT_TEXT_PRIMARY,
                               font=("Consolas", 9),
                               relief=tk.FLAT,
                               borderwidth=0,
                               padx=12,
                               pady=8,
                               yscrollcommand=scrollbar.set,
                               wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.log_text.yview)
        
        # Initial log messages
        self.log_message("JFS SIEM Agent Manager initialized", "info")
        self.log_message(f"Computer: {socket.gethostname()}", "info")
        self.log_message("Ready to start monitoring", "success")
    
    def create_input_field(self, parent, label_text, variable, hint=""):
        """Create a modern input field with label"""
        field_frame = tk.Frame(parent, bg=LIGHT_SURFACE)
        field_frame.pack(fill=tk.X, pady=(0, 16))
        
        # Label
        label = ttk.Label(field_frame, text=label_text, style="Body.TLabel")
        label.pack(anchor=tk.W, pady=(0, 6))
        
        # Entry
        entry = ttk.Entry(field_frame, textvariable=variable, 
                         font=("Segoe UI", 10), style="Modern.TEntry")
        entry.pack(fill=tk.X, ipady=8)
        
        # Hint text
        if hint:
            hint_label = ttk.Label(field_frame, text=hint, style="Caption.TLabel")
            hint_label.pack(anchor=tk.W, pady=(4, 0))
    
    def log_message(self, message, level="info"):
        """Add message to log with color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color based on level
        if level == "error":
            icon = ""
            color = ERROR_RED
        elif level == "success":
            icon = ""
            color = SUCCESS_GREEN
        elif level == "warning":
            icon = ""
            color = WARNING_ORANGE
        else:
            icon = ""
            color = LIGHT_TEXT_SECONDARY
        
        self.log_text.insert(tk.END, f"[{timestamp}] {icon} ", )
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def clear_log(self):
        """Clear log text"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Log cleared", "info")
    
    def test_connection(self):
        """Test connection to collector server"""
        self.log_message("Testing connection to collector...", "info")
        
        try:
            ip = self.collector_ip.get()
            port = int(self.collector_port.get())
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                self.log_message(f"Successfully connected to {ip}:{port}", "success")
                messagebox.showinfo("Connection Test", 
                                  f" Successfully connected to {ip}:{port}")
            else:
                self.log_message(f"Cannot connect to {ip}:{port}", "error")
                messagebox.showerror("Connection Test", 
                                   f" Cannot connect to {ip}:{port}\n\n"
                                   "Make sure the collector server is running.")
        
        except Exception as e:
            self.log_message(f"Connection test failed: {str(e)}", "error")
            messagebox.showerror("Error", f"Connection test failed:\n{str(e)}")
    
    def start_agent(self):
        """Start the agent"""
        if self.agent_running:
            messagebox.showwarning("Warning", "Agent is already running")
            return
        
        self.log_message("Starting agent...", "info")
        self.status_text.set("Starting...")
        self.agent_running = True
        self.start_btn.set_state("disabled")
        self.stop_btn.set_state("normal")
        
        # Run agent in separate thread
        self.agent_thread = threading.Thread(target=self.run_agent, daemon=True)
        self.agent_thread.start()
    
    def run_agent(self):
        """Run agent in background thread"""
        import time
        
        try:
            ip = self.collector_ip.get()
            port = int(self.collector_port.get())
            name = self.agent_name.get()
            
            self.log_message(f"Connecting to {ip}:{port}...", "info")
            self.connection_status.set("Connecting...")
            self.conn_status_label.config(foreground=WARNING_ORANGE)
            self.status_text.set(f"Connecting to {ip}:{port}...")
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            
            self.log_message("Connected to collector", "success")
            self.connection_status.set("Connected")
            self.conn_status_label.config(foreground=SUCCESS_GREEN)
            self.status_indicator.set_status("connected")
            self.status_text.set("Collecting events...")
            
            # Collection loop
            cycle = 0
            while self.agent_running:
                cycle += 1
                self.log_message(f"Collection cycle {cycle} started", "info")
                
                self.collect_and_send_events(sock, name)
                
                self.log_message(f"Waiting 10 seconds...", "info")
                
                for i in range(10):
                    if not self.agent_running:
                        break
                    time.sleep(1)
            
            sock.close()
            self.log_message("Agent stopped", "success")
            self.connection_status.set("Disconnected")
            self.conn_status_label.config(foreground=ERROR_RED)
            self.status_indicator.set_status("disconnected")
            self.status_text.set("Ready to start")
        
        except Exception as e:
            self.log_message(f"Agent error: {str(e)}", "error")
            self.connection_status.set("Error")
            self.conn_status_label.config(foreground=ERROR_RED)
            self.status_indicator.set_status("disconnected")
            self.status_text.set("Error occurred")
            messagebox.showerror("Error", f"Agent error:\n{str(e)}")
        
        finally:
            self.agent_running = False
            self.start_btn.set_state("normal")
            self.stop_btn.set_state("disabled")
    
    def collect_and_send_events(self, sock, agent_name):
        """Collect events and send to server"""
        try:
            import win32evtlog
            import win32con
        except ImportError:
            self.log_message("pywin32 not installed", "error")
            return
        
        total_events = 0
        
        for log_type in ['System', 'Application', 'Security']:
            try:
                hand = win32evtlog.OpenEventLog(None, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                events_sent = 0
                
                for event in events[:50]:
                    try:
                        event_id = event.EventID & 0xFFFF
                        source = event.SourceName
                        timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else None
                        
                        event_type_map = {
                            win32con.EVENTLOG_ERROR_TYPE: 'Error',
                            win32con.EVENTLOG_WARNING_TYPE: 'Warning',
                            win32con.EVENTLOG_INFORMATION_TYPE: 'Information',
                            win32con.EVENTLOG_AUDIT_SUCCESS: 'Audit Success',
                            win32con.EVENTLOG_AUDIT_FAILURE: 'Audit Failure'
                        }
                        event_type = event_type_map.get(event.EventType, 'Unknown')
                        
                        severity_map = {
                            'Error': 'high',
                            'Warning': 'medium',
                            'Audit Failure': 'high',
                            'Information': 'low',
                            'Audit Success': 'info'
                        }
                        severity = severity_map.get(event_type, 'info')
                        
                        try:
                            message = str(event.StringInserts) if event.StringInserts else f"EventID {event_id}"
                        except:
                            message = f"EventID {event_id}"
                        
                        event_data = {
                            'agent': agent_name,
                            'timestamp': timestamp,
                            'log_type': log_type,
                            'event_id': event_id,
                            'source': source,
                            'event_type': event_type,
                            'severity': severity,
                            'message': message[:500],
                            'computer': socket.gethostname()
                        }
                        
                        json_data = json.dumps(event_data) + '\n'
                        sock.sendall(json_data.encode('utf-8'))
                        events_sent += 1
                        total_events += 1
                        
                        self.events_collected.set(str(total_events))
                    
                    except Exception:
                        continue
                
                win32evtlog.CloseEventLog(hand)
                self.log_message(f"Sent {events_sent} {log_type} events", "success")
            
            except Exception as e:
                self.log_message(f"Error collecting {log_type}: {str(e)[:50]}", "error")
    
    def stop_agent(self):
        """Stop the agent"""
        self.agent_running = False
        self.log_message("Stopping agent...", "warning")
        self.status_text.set("Stopping...")
        self.start_btn.set_state("normal")
        self.stop_btn.set_state("disabled")
    
    def install_service(self):
        """Install agent as Windows Service"""
        result = messagebox.askyesno(
            "Install Service",
            "This will install the agent as a Windows Service.\n\n"
            "Requirements:\n"
            " Administrator privileges\n"
            " PowerShell\n\n"
            "The service will run automatically on boot.\n\n"
            "Continue?"
        )
        
        if not result:
            return
        
        self.log_message("Starting service installation...", "info")
        
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            ps_script = os.path.join(script_dir, "install_agent_service.ps1")
            
            ip = self.collector_ip.get()
            port = self.collector_port.get()
            name = self.agent_name.get()
            python_exe = sys.executable
            
            # Create batch file
            batch_content = f"""@echo off
setlocal enabledelayedexpansion
cd /d "{script_dir}"

set LOGFILE={script_dir}\\service.log
echo [%date% %time%] Service started >> %LOGFILE%

:loop
echo [%date% %time%] Starting agent... >> %LOGFILE%
"{python_exe}" jfs_agent.py --server {ip} --port {port} --name {name} >> %LOGFILE% 2>&1
echo [%date% %time%] Agent stopped, restarting... >> %LOGFILE%
timeout /t 10 /nobreak
goto loop
"""
            
            batch_file = os.path.join(script_dir, "run_agent.bat")
            with open(batch_file, 'w', encoding='utf-8') as f:
                f.write(batch_content)
            
            self.log_message("Created service batch file", "success")
            
            # Create PowerShell script
            ps_content = f"""
$ServiceName = 'JFSSIEMAgent'
$DisplayName = 'JFS SIEM Agent - {name}'
$BatchFile = '{batch_file}'

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
    Write-Host "ERROR: Must run as Administrator" -ForegroundColor Red
    pause
    exit 1
}}

net stop $ServiceName 2>$null
sc.exe delete $ServiceName 2>$null
Start-Sleep -Seconds 1

$result = sc.exe create $ServiceName binPath= "cmd.exe /c `"$BatchFile`"" start= auto DisplayName= $DisplayName obj= "LocalSystem"
if ($LASTEXITCODE -eq 0) {{
    Write-Host "[OK] Service created" -ForegroundColor Green
    sc.exe config $ServiceName type= own
    net start $ServiceName
    Write-Host "[OK] Service started" -ForegroundColor Green
}} else {{
    Write-Host "[ERROR] Service creation failed" -ForegroundColor Red
}}
pause
"""
            
            with open(ps_script, 'w', encoding='utf-8') as f:
                f.write(ps_content)
            
            self.log_message("Created PowerShell installer", "success")
            
            # Run PowerShell
            ps_cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{ps_script}"'
            subprocess.Popen(ps_cmd, shell=True)
            
            self.log_message("Service installation started", "success")
            messagebox.showinfo("Service Installation", 
                              "Service installation has been started.\n\n"
                              "Check the PowerShell window for progress.")
        
        except Exception as e:
            self.log_message(f"Service installation failed: {str(e)}", "error")
            messagebox.showerror("Error", f"Service installation failed:\n{str(e)}")

def main():
    root = tk.Tk()
    
    # Set window icon (if available)
    try:
        root.iconbitmap("icon.ico")
    except:
        pass
    
    app = JFSModernAgentGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
