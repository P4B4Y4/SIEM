#!/usr/bin/env python3
"""Test agent registration"""

import requests
import socket
import json

def test_registration():
    hostname = socket.gethostname()
    agent_id = f"agent-{hostname.lower()}"
    
    # Get local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"
    
    payload = {
        'agent_id': agent_id,
        'agent_name': hostname,
        'agent_ip': local_ip,
        'hostname': hostname
    }
    
    print(f"[*] Testing agent registration...")
    print(f"[*] Agent ID: {agent_id}")
    print(f"[*] Hostname: {hostname}")
    print(f"[*] Local IP: {local_ip}")
    print(f"[*] Payload: {json.dumps(payload, indent=2)}")
    
    try:
        url = "http://localhost/SIEM/api/register-agent.php"
        print(f"[*] Sending POST to {url}")
        
        response = requests.post(url, json=payload, timeout=5)
        print(f"[*] Status Code: {response.status_code}")
        print(f"[*] Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"[✓] Agent registered successfully!")
                return True
    except Exception as e:
        print(f"[!] Error: {str(e)}")
    
    return False

if __name__ == '__main__':
    test_registration()
