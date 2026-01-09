"""
JFS WORLD'S #1 SIEM - FortiGate Firewall Connector
Collects firewall logs from FortiGate devices
"""

import mysql.connector
import json
from datetime import datetime
import sys

class FortiGateConnector:
    def __init__(self):
        """Initialize database connection"""
        try:
            self.db = mysql.connector.connect(
                host='localhost',
                user='root',
                password='',
                database='jfs_siem'
            )
            self.cursor = self.db.cursor()
            print("✓ Database connected")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            sys.exit(1)
    
    def collect_firewall_logs(self, mode='simulation'):
        """
        Collect FortiGate firewall logs
        
        Args:
            mode: 'simulation' or 'live' (requires FortiGate API configuration)
        """
        print("\n" + "="*60)
        print("JFS WORLD'S #1 SIEM - FortiGate Firewall Connector")
        print("="*60)
        
        if mode == 'simulation':
            print("\n⚠ Running in SIMULATION mode (test data)")
            print("Configure FortiGate API credentials for live data\n")
            logs = self._generate_test_logs()
        else:
            # TODO: Implement actual FortiGate API integration
            print("Live mode requires FortiGate API configuration")
            return 0
        
        inserted = 0
        for log in logs:
            try:
                query = """
                INSERT INTO security_events 
                (timestamp, event_type, severity, source_ip, destination_ip, 
                 user_account, hostname, process_name, command_line, 
                 raw_log, additional_data, ingestion_source)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                values = (
                    log['timestamp'],
                    log['event_type'],
                    log['severity'],
                    log['source_ip'],
                    log['destination_ip'],
                    None,
                    'FortiGate-FW',
                    None,
                    None,
                    log['raw_log'],
                    json.dumps(log['additional_data']),
                    'fortigate_firewall'
                )
                
                self.cursor.execute(query, values)
                self.db.commit()
                inserted += 1
                
            except Exception as e:
                print(f"⚠ Error inserting log: {str(e)[:100]}")
                continue
        
        print(f"\n✓ Inserted {inserted} FortiGate logs into database")
        return inserted
    
    def _generate_test_logs(self):
        """Generate test FortiGate logs for simulation"""
        log_types = [
            {'action': 'deny', 'reason': 'policy_deny', 'severity': 'high', 'event_type': 'firewall_block'},
            {'action': 'deny', 'reason': 'ips_signature', 'severity': 'critical', 'event_type': 'intrusion_attempt'},
            {'action': 'deny', 'reason': 'botnet_detected', 'severity': 'critical', 'event_type': 'botnet_communication'},
            {'action': 'allow', 'reason': 'policy_allow', 'severity': 'info', 'event_type': 'firewall_allow'},
            {'action': 'deny', 'reason': 'geo_block', 'severity': 'medium', 'event_type': 'geo_violation'},
        ]
        
        logs = []
        for i, log_type in enumerate(log_types):
            for j in range(2):  # 2 logs per type
                log = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': log_type['event_type'],
                    'severity': log_type['severity'],
                    'source_ip': f'203.{100+i}.{50+j}.10',
                    'destination_ip': f'192.168.1.{100+j}',
                    'raw_log': f"FortiGate: action={log_type['action']} reason={log_type['reason']} srcip=203.{100+i}.{50+j}.10 dstip=192.168.1.{100+j}",
                    'additional_data': {
                        'action': log_type['action'],
                        'reason': log_type['reason'],
                        'protocol': 'TCP',
                        'src_port': 443,
                        'dst_port': 443 if j == 0 else 80,
                        'bytes_sent': 1024 * (i+1),
                        'bytes_received': 2048 * (i+1),
                        'device': 'FortiGate-100F',
                        'policy': f'Policy-{i+1}'
                    }
                }
                logs.append(log)
        
        return logs
    
    def close(self):
        """Close database connection"""
        if self.db:
            self.db.close()

if __name__ == '__main__':
    connector = FortiGateConnector()
    connector.collect_firewall_logs(mode='simulation')
    connector.close()
