#!/usr/bin/env python3
"""
SIEM HTTP Agent - Sends events via HTTP POST
"""

import requests
import json
import time
from datetime import datetime

def send_events_http():
    """Send events via HTTP POST"""
    
    collector_url = "http://192.168.1.52/SIEM/api/agent-collector.php"
    
    print(f"Sending events to {collector_url}...")
    
    # Send 10 test events
    for i in range(10):
        event = {
            'agent': 'HTTP-TEST-AGENT',
            'timestamp': datetime.now().isoformat(),
            'log_type': 'Security',
            'event_id': 4624 + i,
            'source': 'Security',
            'event_type': 'windows_event',
            'severity': 'info',
            'what_happened': f'HTTP Test event #{i+1}',
            'computer': 'TEST-PC'
        }
        
        try:
            response = requests.post(collector_url, json=event)
            if response.status_code == 200:
                print(f"[OK] Event #{i+1} sent")
            else:
                print(f"[ERROR] Event #{i+1} failed: {response.status_code}")
        except Exception as e:
            print(f"[ERROR] {e}")
        
        time.sleep(0.5)
    
    print("[OK] Done!")

if __name__ == '__main__':
    send_events_http()
