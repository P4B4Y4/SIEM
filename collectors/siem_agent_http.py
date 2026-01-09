#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM HTTP Agent - Sends Windows events via HTTP POST
"""

import requests
import json
import time
import sys
import argparse
from datetime import datetime

try:
    import win32evtlog
    import win32con
except ImportError:
    print("ERROR: pywin32 not installed. Run: pip install pywin32")
    sys.exit(1)

class SIEMHTTPAgent:
    def __init__(self, server_ip, server_port=80, pc_name=None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.pc_name = pc_name or "UNKNOWN-PC"
        self.collector_url = f"http://{server_ip}:{server_port}/SIEM/api/agent-collector.php"
        self.events_sent = 0
    
    def send_event(self, event_data):
        """Send event via HTTP POST"""
        try:
            response = requests.post(self.collector_url, json=event_data, timeout=5)
            if response.status_code == 200:
                self.events_sent += 1
                return True
            else:
                print(f"[ERROR] HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Send failed: {e}")
            return False
    
    def collect_security_events(self):
        """Collect Windows Security events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 20:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    severity_map = {
                        win32con.EVENTLOG_ERROR_TYPE: 'high',
                        win32con.EVENTLOG_WARNING_TYPE: 'medium',
                        win32con.EVENTLOG_INFORMATION_TYPE: 'low',
                        win32con.EVENTLOG_AUDIT_SUCCESS: 'info',
                        win32con.EVENTLOG_AUDIT_FAILURE: 'high'
                    }
                    
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': timestamp,
                        'log_type': 'Security',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'windows_event',
                        'severity': severity_map.get(event.EventType, 'info'),
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
            print(f"[ERROR] Collection failed: {e}")
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
                        'severity': 'info',
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
            print(f"[ERROR] System events failed: {e}")
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
                        'severity': 'info',
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
            print(f"[ERROR] Application events failed: {e}")
            return 0
    
    def run(self):
        """Main loop"""
        print(f"\n{'='*70}")
        print(f"SIEM HTTP Agent")
        print(f"{'='*70}")
        print(f"PC: {self.pc_name}")
        print(f"Server: {self.server_ip}:{self.server_port}")
        print(f"Collector: {self.collector_url}")
        print(f"{'='*70}\n")
        
        cycle = 0
        while True:
            cycle += 1
            
            print(f"[Cycle {cycle}] Collecting events...")
            
            try:
                sec_count = self.collect_security_events()
                sys_count = self.collect_system_events()
                app_count = self.collect_application_events()
                
                total = sec_count + sys_count + app_count
                print(f"[Cycle {cycle}] Sent {total} events (Security: {sec_count}, System: {sys_count}, App: {app_count})")
                print(f"[Cycle {cycle}] Total events sent: {self.events_sent}")
            
            except Exception as e:
                print(f"[ERROR] Collection failed: {e}")
            
            print(f"[Cycle {cycle}] Waiting 10 seconds...\n")
            time.sleep(10)

def main():
    parser = argparse.ArgumentParser(description='SIEM HTTP Agent')
    parser.add_argument('--server', required=True, help='Collector server IP')
    parser.add_argument('--port', type=int, default=80, help='Collector port (default: 80)')
    parser.add_argument('--name', help='PC name')
    
    args = parser.parse_args()
    
    agent = SIEMHTTPAgent(args.server, args.port, args.name)
    agent.run()

if __name__ == '__main__':
    main()
