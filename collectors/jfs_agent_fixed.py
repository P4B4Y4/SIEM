# -*- coding: utf-8 -*-
"""
JFS SIEM - Fixed Agent for Remote PC
Sends Windows event logs to SIEM collector continuously
"""

import sys
import os
import json
import socket
import argparse
import time
import threading
from datetime import datetime

try:
    import win32evtlog
    import win32con
except ImportError:
    print("ERROR: pywin32 not installed. Run: pip install pywin32")
    sys.exit(1)

class JFSAgentFixed:
    def __init__(self, server_ip, server_port=9999, pc_name=None):
        """Initialize agent"""
        self.server_ip = server_ip
        self.server_port = server_port
        self.pc_name = pc_name or socket.gethostname()
        self.socket = None
        self.events_sent = 0
        self.connected = False
        
    def connect(self):
        """Connect to collector server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            self.connected = True
            print(f"[OK] Connected to {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            self.connected = False
            return False
    
    def send_event(self, event_data):
        """Send event to collector"""
        if not self.connected:
            return False
        
        try:
            json_data = json.dumps(event_data) + '\n'
            self.socket.sendall(json_data.encode('utf-8'))
            self.events_sent += 1
            return True
        except Exception as e:
            print(f"[ERROR] Send failed: {e}")
            self.connected = False
            return False
    
    def collect_security_events(self):
        """Collect Windows Security events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 20:  # Limit to 20 events per cycle
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': timestamp,
                        'log_type': 'Security',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'windows_event',
                        'severity': self._get_severity(event.EventType),
                        'what_happened': f"Event {event_id} from {event.SourceName}",
                        'computer': self.pc_name
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except Exception as e:
            print(f"[ERROR] Security events: {e}")
            return 0
    
    def collect_system_events(self):
        """Collect Windows System events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 10:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': timestamp,
                        'log_type': 'System',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'system_event',
                        'severity': self._get_severity(event.EventType),
                        'what_happened': f"System event {event_id}",
                        'computer': self.pc_name
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except Exception as e:
            print(f"[ERROR] System events: {e}")
            return 0
    
    def collect_application_events(self):
        """Collect Windows Application events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'Application')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 10:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': timestamp,
                        'log_type': 'Application',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'application_event',
                        'severity': self._get_severity(event.EventType),
                        'what_happened': f"Application event {event_id}",
                        'computer': self.pc_name
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except Exception as e:
            print(f"[ERROR] Application events: {e}")
            return 0
    
    def _get_severity(self, event_type):
        """Map Windows event type to severity"""
        severity_map = {
            win32con.EVENTLOG_ERROR_TYPE: 'high',
            win32con.EVENTLOG_WARNING_TYPE: 'medium',
            win32con.EVENTLOG_INFORMATION_TYPE: 'low',
            win32con.EVENTLOG_AUDIT_SUCCESS: 'info',
            win32con.EVENTLOG_AUDIT_FAILURE: 'high'
        }
        return severity_map.get(event_type, 'info')
    
    def run(self):
        """Main agent loop - continuous collection"""
        print(f"\n{'='*70}")
        print(f"JFS SIEM Agent - Fixed Version")
        print(f"{'='*70}")
        print(f"PC Name: {self.pc_name}")
        print(f"Server: {self.server_ip}:{self.server_port}")
        print(f"{'='*70}\n")
        
        cycle = 0
        while True:
            cycle += 1
            
            # Try to connect if not connected
            if not self.connected:
                print(f"[Cycle {cycle}] Connecting...")
                if not self.connect():
                    print("Retrying in 5 seconds...")
                    time.sleep(5)
                    continue
            
            print(f"[Cycle {cycle}] Collecting events...")
            
            try:
                # Collect events from all sources
                sec_count = self.collect_security_events()
                sys_count = self.collect_system_events()
                app_count = self.collect_application_events()
                
                total = sec_count + sys_count + app_count
                print(f"[Cycle {cycle}] Sent {total} events (Security: {sec_count}, System: {sys_count}, App: {app_count})")
                print(f"[Cycle {cycle}] Total events sent: {self.events_sent}")
                
            except Exception as e:
                print(f"[ERROR] Collection failed: {e}")
                self.connected = False
            
            # Wait before next cycle
            print(f"[Cycle {cycle}] Waiting 10 seconds...\n")
            time.sleep(10)

def main():
    parser = argparse.ArgumentParser(description='JFS SIEM Fixed Agent')
    parser.add_argument('--server', required=True, help='Collector server IP')
    parser.add_argument('--port', type=int, default=9999, help='Collector port')
    parser.add_argument('--name', help='PC name')
    
    args = parser.parse_args()
    
    agent = JFSAgentFixed(args.server, args.port, args.name)
    agent.run()

if __name__ == '__main__':
    main()
