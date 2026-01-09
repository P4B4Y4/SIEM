# -*- coding: utf-8 -*-
"""
JFS SIEM - Lightweight Agent for Remote PC
Runs on remote PC and sends event logs to collector server
Completely FREE - no external dependencies beyond pywin32

INSTALLATION:
1. Copy this file to remote PC
2. Run: python jfs_agent.py --server <collector_ip> --port 9999
3. Or schedule as Windows Task for continuous collection
"""

import sys
import os
import json
import socket
import argparse
import time
import subprocess
import psutil
from datetime import datetime
import win32evtlog
import win32con

class JFSAgent:
    def __init__(self, server_ip, server_port=9999, pc_name=None):
        """Initialize agent"""
        self.server_ip = server_ip
        self.server_port = server_port
        self.pc_name = pc_name or socket.gethostname()
        self.socket = None
        self.events_sent = 0
        # Track last event record numbers per log type to avoid duplicates
        self.last_record_numbers = {
            'System': 0,
            'Application': 0,
            'Security': 0
        }
    
    def connect_to_server(self):
        """Connect to collector server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            print(f"✓ Connected to collector at {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            print(f"✗ Cannot connect to server: {e}")
            return False
    
    def send_event(self, event_data):
        """Send event to collector server"""
        try:
            # Convert to JSON and add newline delimiter
            json_data = json.dumps(event_data) + '\n'
            self.socket.sendall(json_data.encode('utf-8'))
            self.events_sent += 1
            return True
        except Exception as e:
            print(f"✗ Error sending event: {e}")
            return False
    
    def get_clear_description(self, event_id, inserts, source):
        """Convert event data to clear, human-readable description"""
        try:
            inserts = inserts or []
            
            # Map event IDs to clear descriptions
            descriptions = {
                # Authentication
                4624: f"User '{inserts[1] if len(inserts) > 1 else 'Unknown'}' logged in from {inserts[18] if len(inserts) > 18 else 'Local'}",
                4625: f"Failed login attempt for '{inserts[1] if len(inserts) > 1 else 'Unknown'}'",
                4634: f"User '{inserts[1] if len(inserts) > 1 else 'Unknown'}' logged out",
                4648: f"User '{inserts[1] if len(inserts) > 1 else 'Unknown'}' ran command as different user",
                
                # Privileges
                4672: f"Admin privileges assigned to '{inserts[1] if len(inserts) > 1 else 'Unknown'}'",
                4673: f"Sensitive privilege used by '{inserts[1] if len(inserts) > 1 else 'Unknown'}'",
                
                # Process & Service
                4688: f"Program executed: {inserts[5] if len(inserts) > 5 else 'Unknown'} by {inserts[1] if len(inserts) > 1 else 'Unknown'}",
                4697: f"Service installed: {inserts[0] if len(inserts) > 0 else 'Unknown'}",
                4698: f"Scheduled task created: {inserts[0] if len(inserts) > 0 else 'Unknown'}",
                4702: f"Scheduled task updated: {inserts[0] if len(inserts) > 0 else 'Unknown'}",
                
                # Account Management
                4720: f"New user account created: {inserts[0] if len(inserts) > 0 else 'Unknown'}",
                4726: f"User account deleted: {inserts[0] if len(inserts) > 0 else 'Unknown'}",
                4728: f"User '{inserts[0] if len(inserts) > 0 else 'Unknown'}' added to group '{inserts[1] if len(inserts) > 1 else 'Unknown'}'",
                4732: f"User '{inserts[0] if len(inserts) > 0 else 'Unknown'}' added to group '{inserts[1] if len(inserts) > 1 else 'Unknown'}'",
                4756: f"User '{inserts[0] if len(inserts) > 0 else 'Unknown'}' added to group '{inserts[1] if len(inserts) > 1 else 'Unknown'}'",
                4740: f"Account locked: {inserts[0] if len(inserts) > 0 else 'Unknown'}",
                4723: f"Password changed for '{inserts[0] if len(inserts) > 0 else 'Unknown'}'",
                4724: f"Password reset for '{inserts[0] if len(inserts) > 0 else 'Unknown'}'",
                
                # Network & File
                5140: f"Network share accessed: {inserts[0] if len(inserts) > 0 else 'Unknown'} by {inserts[1] if len(inserts) > 1 else 'Unknown'}",
                5156: f"Firewall allowed connection from {inserts[2] if len(inserts) > 2 else 'Unknown'} to {inserts[3] if len(inserts) > 3 else 'Unknown'}",
                5157: f"Firewall blocked connection from {inserts[2] if len(inserts) > 2 else 'Unknown'} to {inserts[3] if len(inserts) > 3 else 'Unknown'}",
                
                # System Changes
                4719: "Audit policy was changed",
                4765: f"SID history added to '{inserts[0] if len(inserts) > 0 else 'Unknown'}'",
                4781: f"Account renamed from '{inserts[0] if len(inserts) > 0 else 'Unknown'}' to '{inserts[1] if len(inserts) > 1 else 'Unknown'}'",
            }
            
            return descriptions.get(event_id, f"Event {event_id} from {source}")
        except:
            return f"Event {event_id} from {source}"
    
    def collect_events(self, log_type='Security', max_events=500):
        """Collect ALL events with CLEAR descriptions of what actually happened"""
        
        print(f"\n{'='*70}")
        print(f"Collecting ALL {log_type} events with CLEAR descriptions...")
        print(f"{'='*70}")
        
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            events_found = 0
            for event in events:
                if events_found >= max_events:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    source = event.SourceName
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else None
                    
                    # Get clear description of what happened
                    what_happened = self.get_clear_description(event_id, event.StringInserts, source)
                    
                    # Determine severity
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
                    
                    events_found += 1
                    
                    # Build clear event data
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'event_id': event_id,
                        'source': source,
                        'event_type': event_type,
                        'severity': severity,
                        'what_happened': what_happened[:1000],  # CLEAR description
                        'computer': event.ComputerName if hasattr(event, 'ComputerName') else self.pc_name
                    }
                    
                    # Send to server
                    if self.send_event(event_data):
                        if self.events_sent % 10 == 0:
                            print(f"  Sent {self.events_sent} events - {what_happened[:50]}...")
                    
                except Exception as e:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            print(f"✓ Collected {events_found} events from {log_type}")
            
        except Exception as e:
            print(f"✗ Error accessing {log_type}: {e}")
    
    def collect_powershell_logs(self):
        """Collect PowerShell command history and execution logs"""
        try:
            print("\n" + "="*70)
            print("Collecting PowerShell Logs...")
            print("="*70)
            
            # Collect from PowerShell event log
            for log_name in ['Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational']:
                try:
                    hand = win32evtlog.OpenEventLog(None, log_name)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events[:30]:
                        try:
                            event_data = {
                                'agent': self.pc_name,
                                'timestamp': event.TimeGenerated.isoformat() if event.TimeGenerated else None,
                                'log_type': 'PowerShell',
                                'event_id': event.EventID & 0xFFFF,
                                'source': event.SourceName,
                                'event_type': 'powershell_execution',
                                'severity': 'medium',
                                'message': str(event.StringInserts)[:500] if event.StringInserts else 'PowerShell event',
                                'computer': self.pc_name
                            }
                            self.send_event(event_data)
                        except:
                            continue
                    
                    win32evtlog.CloseEventLog(hand)
                except:
                    continue
            
            print(f"✓ PowerShell logs collected")
        except Exception as e:
            print(f"⚠ Error collecting PowerShell logs: {e}")
    
    def collect_firewall_logs(self):
        """Collect Windows Firewall blocked connections"""
        try:
            print("\n" + "="*70)
            print("Collecting Firewall Logs...")
            print("="*70)
            
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 30:
                    break
                try:
                    event_id = event.EventID & 0xFFFF
                    # Firewall events: 5156, 5157, 5158, 5159
                    if event_id in [5156, 5157, 5158, 5159]:
                        event_data = {
                            'agent': self.pc_name,
                            'timestamp': event.TimeGenerated.isoformat() if event.TimeGenerated else None,
                            'log_type': 'Firewall',
                            'event_id': event_id,
                            'source': 'Windows Firewall',
                            'event_type': 'firewall_connection',
                            'severity': 'medium',
                            'message': str(event.StringInserts)[:500] if event.StringInserts else f'Firewall event {event_id}',
                            'computer': self.pc_name
                        }
                        self.send_event(event_data)
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            print(f"✓ Firewall logs collected ({count} events)")
        except Exception as e:
            print(f"⚠ Error collecting Firewall logs: {e}")
    
    def collect_process_list(self):
        """Collect running processes"""
        try:
            print("\n" + "="*70)
            print("Collecting Process List...")
            print("="*70)
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'username'])
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': datetime.now().isoformat(),
                        'log_type': 'Process',
                        'event_id': pinfo['pid'],
                        'source': 'Process Monitor',
                        'event_type': 'process_running',
                        'severity': 'info',
                        'message': f"{pinfo['name']} - {' '.join(pinfo['cmdline'] or [])}",
                        'computer': self.pc_name,
                        'username': pinfo['username']
                    }
                    self.send_event(event_data)
                except:
                    continue
            
            print(f"✓ Process list collected")
        except Exception as e:
            print(f"⚠ Error collecting process list: {e}")
    
    def collect_network_connections(self):
        """Collect active network connections"""
        try:
            print("\n" + "="*70)
            print("Collecting Network Connections...")
            print("="*70)
            
            connections = psutil.net_connections()
            count = 0
            
            for conn in connections[:50]:  # Limit to 50 connections
                try:
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': datetime.now().isoformat(),
                        'log_type': 'Network',
                        'event_id': 0,
                        'source': 'Network Monitor',
                        'event_type': 'network_connection',
                        'severity': 'info',
                        'message': f"{conn.type} - {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else 'LISTENING'}:{conn.raddr.port if conn.raddr else 'N/A'}",
                        'computer': self.pc_name,
                        'status': conn.status
                    }
                    self.send_event(event_data)
                    count += 1
                except:
                    continue
            
            print(f"✓ Network connections collected ({count} connections)")
        except Exception as e:
            print(f"⚠ Error collecting network connections: {e}")
    
    def collect_system_performance(self):
        """Collect system performance metrics"""
        try:
            print("\n" + "="*70)
            print("Collecting System Performance...")
            print("="*70)
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics = [
                {'metric': 'CPU Usage', 'value': f"{cpu_percent}%", 'severity': 'high' if cpu_percent > 80 else 'info'},
                {'metric': 'Memory Usage', 'value': f"{memory.percent}%", 'severity': 'high' if memory.percent > 80 else 'info'},
                {'metric': 'Disk Usage', 'value': f"{disk.percent}%", 'severity': 'high' if disk.percent > 90 else 'info'},
            ]
            
            for metric in metrics:
                event_data = {
                    'agent': self.pc_name,
                    'timestamp': datetime.now().isoformat(),
                    'log_type': 'Performance',
                    'event_id': 0,
                    'source': 'Performance Monitor',
                    'event_type': 'performance_metric',
                    'severity': metric['severity'],
                    'message': f"{metric['metric']}: {metric['value']}",
                    'computer': self.pc_name
                }
                self.send_event(event_data)
            
            print(f"✓ System performance collected")
        except Exception as e:
            print(f"⚠ Error collecting system performance: {e}")
    
    def collect_dns_logs(self):
        """Collect DNS client events"""
        try:
            print("\n" + "="*70)
            print("Collecting DNS Logs...")
            print("="*70)
            
            hand = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 20:
                    break
                try:
                    if 'DNS' in event.SourceName or event.EventID & 0xFFFF in [1014, 1015]:
                        event_data = {
                            'agent': self.pc_name,
                            'timestamp': event.TimeGenerated.isoformat() if event.TimeGenerated else None,
                            'log_type': 'DNS',
                            'event_id': event.EventID & 0xFFFF,
                            'source': event.SourceName,
                            'event_type': 'dns_query',
                            'severity': 'info',
                            'message': str(event.StringInserts)[:500] if event.StringInserts else 'DNS event',
                            'computer': self.pc_name
                        }
                        self.send_event(event_data)
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            print(f"✓ DNS logs collected ({count} events)")
        except Exception as e:
            print(f"⚠ Error collecting DNS logs: {e}")
    
    def collect_all(self):
        """Collect from all log types - runs continuously with persistent connection"""
        if not self.connect_to_server():
            print("✗ Cannot proceed without server connection")
            return False
        
        print("\n" + "="*70)
        print("JFS SIEM - Remote Agent Collection (Continuous Mode)")
        print("="*70)
        print(f"Agent: {self.pc_name}")
        print(f"Server: {self.server_ip}:{self.server_port}")
        print("Collecting events continuously...")
        print("="*70)
        
        # Keep collecting in a loop with persistent connection
        cycle = 0
        try:
            while True:
                cycle += 1
                print(f"\n[Cycle {cycle}] Starting comprehensive collection...")
                
                # Collect Windows Event Logs
                for log_type in ['System', 'Application', 'Security']:
                    try:
                        self.collect_events(log_type, max_events=50)
                    except Exception as e:
                        print(f"✗ Error collecting {log_type}: {e}")
                
                # Collect additional data sources
                try:
                    self.collect_powershell_logs()
                except:
                    pass
                
                try:
                    self.collect_firewall_logs()
                except:
                    pass
                
                try:
                    self.collect_dns_logs()
                except:
                    pass
                
                try:
                    self.collect_process_list()
                except:
                    pass
                
                try:
                    self.collect_network_connections()
                except:
                    pass
                
                try:
                    self.collect_system_performance()
                except:
                    pass
                
                print(f"[Cycle {cycle}] Total events sent so far: {self.events_sent}")
                print("Waiting 10 seconds before next collection...")
                
                # Wait 10 seconds before next collection
                time.sleep(10)
        
        except KeyboardInterrupt:
            print("\n\nAgent stopped by user")
        except Exception as e:
            print(f"\n✗ Connection error: {e}")
            print("Reconnecting...")
            time.sleep(5)
            return self.collect_all()  # Reconnect and retry
        finally:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
        
        return True

def main():
    parser = argparse.ArgumentParser(description='JFS SIEM Remote Agent')
    parser.add_argument('--server', required=True, help='Collector server IP address')
    parser.add_argument('--port', type=int, default=9999, help='Collector server port (default: 9999)')
    parser.add_argument('--name', help='PC name (default: hostname)')
    
    args = parser.parse_args()
    
    agent = JFSAgent(args.server, args.port, args.name)
    agent.collect_all()

if __name__ == '__main__':
    main()
