#!/usr/bin/env python3
"""
Test Agent - Sends fake events to collector
"""

import socket
import json
import time
from datetime import datetime

def send_fake_events():
    """Send fake test events to collector"""
    
    server_ip = "192.168.1.52"
    server_port = 9999
    
    print(f"Connecting to {server_ip}:{server_port}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, server_port))
        print("[OK] Connected!")
        
        # Send 10 fake events
        for i in range(10):
            event = {
                'agent': 'TEST-AGENT',
                'timestamp': datetime.now().isoformat(),
                'log_type': 'Security',
                'event_id': 4624 + i,
                'source': 'Security',
                'event_type': 'windows_event',
                'severity': 'info',
                'what_happened': f'Test event #{i+1} from fake agent',
                'computer': 'TEST-PC'
            }
            
            json_str = json.dumps(event) + '\n'
            sock.sendall(json_str.encode('utf-8'))
            print(f"[OK] Sent event #{i+1}")
            time.sleep(0.5)
        
        sock.close()
        print("[OK] Done!")
        
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == '__main__':
    send_fake_events()
