"""
JFS WORLD'S #1 SIEM - Master Collector Script
Runs all data collectors in sequence
"""

import subprocess
import sys
import os
from datetime import datetime

def run_collector(script_name, description):
    """Run a collector script and report results"""
    print("\n" + "="*70)
    print(f"Running: {description}")
    print("="*70)
    
    try:
        result = subprocess.run(
            [sys.executable, script_name],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(result.stdout)
        if result.stderr:
            print(f"Errors: {result.stderr}")
        
        return result.returncode == 0
    
    except subprocess.TimeoutExpired:
        print(f"✗ Timeout: {script_name} took longer than 60 seconds")
        return False
    except Exception as e:
        print(f"✗ Failed to run {script_name}: {e}")
        return False

def main():
    """Run all collectors"""
    print("\n╔══════════════════════════════════════════════════════════════════════════╗")
    print("║           JFS WORLD'S #1 SIEM - MASTER DATA COLLECTION SYSTEM           ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
    print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    collectors = [
        ('windows_events.py', 'Windows Event Log Collector (Security, System, Application)'),
        ('eset_connector.py', 'ESET Security Connector (Malware Detections)'),
        ('fortigate_connector.py', 'FortiGate Firewall Connector (Network Logs)'),
    ]
    
    results = {}
    
    for script, description in collectors:
        script_path = os.path.join(script_dir, script)
        
        if not os.path.exists(script_path):
            print(f"\n⚠ Warning: {script} not found at {script_path}")
            results[description] = False
            continue
        
        success = run_collector(script_path, description)
        results[description] = success
    
    # Summary
    print("\n" + "="*70)
    print("COLLECTION SUMMARY")
    print("="*70)
    
    for description, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        print(f"{status:12} | {description}")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    print(f"\nTotal: {passed}/{total} collectors succeeded")
    print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Exit with appropriate code
    sys.exit(0 if passed == total else 1)

if __name__ == '__main__':
    main()
