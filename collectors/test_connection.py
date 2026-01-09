#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test connection to collector server
Run this on the remote PC to diagnose connection issues
"""

import socket
import sys
import time

def test_connection(host, port, timeout=5):
    """Test TCP connection to host:port"""
    print(f"\n{'='*70}")
    print(f"Testing connection to {host}:{port}")
    print(f"{'='*70}\n")
    
    # Test 1: DNS Resolution
    print("[1/4] Testing DNS resolution...")
    try:
        ip = socket.gethostbyname(host)
        print(f"  ✓ Resolved {host} to {ip}")
    except socket.gaierror as e:
        print(f"  ✗ DNS resolution failed: {e}")
        return False
    
    # Test 2: Socket Creation
    print("\n[2/4] Creating socket...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        print(f"  ✓ Socket created successfully")
    except Exception as e:
        print(f"  ✗ Socket creation failed: {e}")
        return False
    
    # Test 3: Connection Attempt
    print(f"\n[3/4] Attempting connection to {host}:{port}...")
    try:
        sock.connect((host, port))
        print(f"  ✓ Connected successfully!")
        
        # Test 4: Send/Receive
        print(f"\n[4/4] Testing data transmission...")
        test_msg = '{"test": "connection"}\n'
        sock.sendall(test_msg.encode('utf-8'))
        print(f"  ✓ Sent test message: {test_msg.strip()}")
        
        sock.close()
        print(f"\n{'='*70}")
        print("✓ CONNECTION TEST PASSED")
        print(f"{'='*70}\n")
        return True
        
    except socket.timeout:
        print(f"  ✗ Connection timed out (no response after {timeout}s)")
        print(f"\n  Possible causes:")
        print(f"    - Collector server not running")
        print(f"    - Firewall blocking port {port}")
        print(f"    - Network connectivity issue")
        sock.close()
        return False
        
    except ConnectionRefused:
        print(f"  ✗ Connection refused (port {port} not open)")
        print(f"\n  Possible causes:")
        print(f"    - Collector server not running")
        print(f"    - Service not listening on port {port}")
        sock.close()
        return False
        
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        sock.close()
        return False

def main():
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = "192.168.1.100"
    
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port = 9999
    
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "JFS SIEM - Connection Test" + " "*27 + "║")
    print("╚" + "="*68 + "╝")
    
    success = test_connection(host, port)
    
    if success:
        print("Next steps:")
        print("  1. Agent can now connect to collector")
        print("  2. Deploy JFS_SIEM_Agent.exe to remote PC")
        print("  3. Run GUI and click 'Install Service'")
        print("  4. Service will start collecting events")
    else:
        print("Troubleshooting:")
        print("  1. Verify collector server is running")
        print("  2. Check firewall allows port 9999")
        print("  3. Verify network connectivity (ping 192.168.1.100)")
        print("  4. Check collector IP address is correct")
        print("  5. Run: netstat -ano | findstr :9999 on collector PC")
    
    print()

if __name__ == '__main__':
    main()
