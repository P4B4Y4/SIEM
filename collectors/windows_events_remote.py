# -*- coding: utf-8 -*-
"""
JFS WORLD'S #1 SIEM - Windows Event Collector with REMOTE PC Support
Collects logs from multiple Windows PCs on the network
FIXED: Reads configuration from remote_pcs.ini
"""

import sys
import os
import io

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Set UTF-8 encoding for stdout
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import win32evtlog
import win32con
import win32security
import json
from datetime import datetime
import traceback
from common.config_manager import get_config_manager
from common.database_manager import DatabaseManager
from common.logger import get_logger

# Initialize components
config = get_config_manager()
logger = get_logger('windows_events_remote')
db = DatabaseManager()

# Get remote PCs configuration
remote_pcs_config = config.get_remote_pcs_config()
REMOTE_PCS = []

# Parse PC list from config
for pc in remote_pcs_config['pcs']:
    REMOTE_PCS.append((pc['name'], pc['username'], pc['password']))

# Collection settings
MAX_EVENTS_PER_LOG = remote_pcs_config['max_events_per_log']
COLLECT_SECURITY = remote_pcs_config['collect_security']
COLLECT_SYSTEM = remote_pcs_config['collect_system']
COLLECT_APPLICATION = remote_pcs_config['collect_application']
CONNECTION_TIMEOUT = remote_pcs_config['connection_timeout']

logger.info(f"Loaded configuration: {len(REMOTE_PCS)} PCs to monitor")
logger.info(f"Collection settings: Security={COLLECT_SECURITY}, System={COLLECT_SYSTEM}, Application={COLLECT_APPLICATION}")

class RemoteWindowsEventCollector:
    def __init__(self):
        """Initialize database connection"""
        try:
            self.db = db
            if self.db.test_connection():
                print("✓ Database connected")
                logger.info("Database connection established")
            else:
                raise Exception("Database connection test failed")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            logger.error(f"Database connection failed: {e}")
            sys.exit(1)
    
    def check_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return win32security.IsUserAnAdmin()
        except Exception:
            return False
    
    def datetime_to_string(self, dt):
        """Convert datetime to ISO format string"""
        if dt is None:
            return None
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt)
    
    def test_remote_connection(self, computer_name):
        """Test if we can connect to remote PC"""
        if computer_name == 'localhost':
            return True
        
        try:
            # Try to open System log (least privileged)
            hand = win32evtlog.OpenEventLog(computer_name, 'System')
            win32evtlog.CloseEventLog(hand)
            return True
        except Exception as e:
            print(f"  ✗ Cannot connect to {computer_name}: {str(e)[:100]}")
            return False
    
    def collect_from_pc(self, computer_name, log_type='System', max_events=50):
        """
        Collect events from a specific PC
        
        Args:
            computer_name: Name of the PC ('localhost' or 'PC-NAME')
            log_type: 'Security', 'System', or 'Application'
            max_events: Maximum events to collect
        """
        print(f"\n{'='*70}")
        print(f"PC: {computer_name} | Log: {log_type}")
        print(f"{'='*70}")
        
        # Security log needs admin - try anyway, will fail gracefully
        if log_type == 'Security' and computer_name == 'localhost':
            if not self.check_privileges():
                print(f"⚠ WARNING: Security log requires Administrator privileges")
                print(f"ℹ Attempting to collect anyway (may fail)...")
                logger.warning(f"Attempting Security log collection without admin privileges")
        
        events_inserted = 0
        
        try:
            # Open event log (LOCAL or REMOTE)
            if computer_name == 'localhost':
                hand = win32evtlog.OpenEventLog(None, log_type)
            else:
                # Connect to REMOTE PC
                hand = win32evtlog.OpenEventLog(computer_name, log_type)
            
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events[:max_events]:
                try:
                    # Extract event data
                    event_id = event.EventID & 0xFFFF
                    source = event.SourceName
                    timestamp = self.datetime_to_string(event.TimeGenerated)
                    
                    # Event type
                    event_type_map = {
                        win32con.EVENTLOG_ERROR_TYPE: 'Error',
                        win32con.EVENTLOG_WARNING_TYPE: 'Warning',
                        win32con.EVENTLOG_INFORMATION_TYPE: 'Information',
                        win32con.EVENTLOG_AUDIT_SUCCESS: 'Audit Success',
                        win32con.EVENTLOG_AUDIT_FAILURE: 'Audit Failure'
                    }
                    event_type = event_type_map.get(event.EventType, 'Unknown')
                    
                    # Message
                    try:
                        message = str(event.StringInserts) if event.StringInserts else f"EventID {event_id}"
                    except:
                        message = f"EventID {event_id}"
                    
                    # Severity
                    severity_map = {
                        'Error': 'high',
                        'Warning': 'medium',
                        'Audit Failure': 'high',
                        'Information': 'low',
                        'Audit Success': 'info'
                    }
                    severity = severity_map.get(event_type, 'info')
                    
                    # SIEM event type
                    siem_event_type = self.map_event_type(log_type, event_id, event_type)
                    
                    # Additional data (JSON)
                    additional_data = {
                        'log_type': log_type,
                        'event_id': event_id,
                        'source': source,
                        'event_type': event_type,
                        'remote_pc': computer_name,  # Track which PC
                        'computer': event.ComputerName if hasattr(event, 'ComputerName') else computer_name,
                        'category': event.EventCategory if hasattr(event, 'EventCategory') else 0,
                    }
                    
                    # Insert into database
                    query = """
                    INSERT INTO security_events 
                    (timestamp, event_type, severity, source_ip, 
                     process_name, raw_log, event_data, user_account)
                    VALUES (%(timestamp)s, %(event_type)s, %(severity)s, %(source_ip)s, 
                            %(process_name)s, %(raw_log)s, %(event_data)s, %(user_account)s)
                    """
                    
                    params = {
                        'timestamp': timestamp,
                        'event_type': siem_event_type,
                        'severity': severity,
                        'source_ip': self.resolve_ip(computer_name),
                        'process_name': source,
                        'raw_log': message[:1000],
                        'event_data': json.dumps(additional_data),
                        'user_account': computer_name  # Store PC name as user_account for tracking
                    }
                    
                    self.db.execute_query(query, params)
                    events_inserted += 1
                    
                    if events_inserted % 10 == 0:
                        print(f"  Inserted {events_inserted} events...")
                
                except Exception as e:
                    print(f"⚠ Error inserting event: {str(e)[:100]}")
                    continue
            
            win32evtlog.CloseEventLog(hand)
            print(f"✓ Collected {events_inserted} events from {computer_name}")
            return events_inserted
            
        except Exception as e:
            print(f"✗ Error accessing {computer_name}/{log_type}: {str(e)[:150]}")
            return 0
    
    def resolve_ip(self, computer_name):
        """Try to resolve computer name to IP"""
        if computer_name == 'localhost':
            return '127.0.0.1'
        try:
            import socket
            return socket.gethostbyname(computer_name)
        except:
            return '0.0.0.0'
    
    def map_event_type(self, log_type, event_id, event_type):
        """Map Windows event to SIEM event type"""
        if log_type == 'Security':
            if event_id in [4624]:
                return 'login'
            elif event_id in [4634, 4647]:
                return 'logout'
            elif event_id in [4672]:
                return 'privilege_escalation'
            elif event_id in [4688]:
                return 'process_execution'
            elif event_id in [4625]:
                return 'failed_login'
        elif log_type == 'System':
            if event_type == 'Error':
                return 'system_error'
            elif event_type == 'Warning':
                return 'system_warning'
        elif log_type == 'Application':
            if event_type == 'Error':
                return 'application_error'
        
        return 'windows_event'
    
    def collect_all(self):
        """Collect logs from ALL configured PCs"""
        print("\n" + "="*70)
        print("JFS SIEM - Multi-PC Windows Event Collection")
        print("="*70)
        print(f"\nMonitoring {len(REMOTE_PCS)} PCs: {[pc[0] for pc in REMOTE_PCS]}")
        print("")
        
        total_events = 0
        successful_pcs = 0
        
        for pc_config in REMOTE_PCS:
            computer_name = pc_config[0]
            
            # Test connection first
            if not self.test_remote_connection(computer_name):
                print(f"⚠ Skipping {computer_name} (cannot connect)\n")
                continue
            
            successful_pcs += 1
            
            # Collect from each log type
            for log_type in ['System', 'Application', 'Security']:
                events = self.collect_from_pc(computer_name, log_type, max_events=30)
                total_events += events
        
        print("\n" + "="*70)
        print(f"COLLECTION COMPLETE")
        print(f"  Connected PCs: {successful_pcs}/{len(REMOTE_PCS)}")
        print(f"  TOTAL EVENTS INSERTED: {total_events}")
        print("="*70)
        
        return total_events

def main():
    print("="*70)
    print("JFS WORLD'S #1 SIEM - Multi-PC Windows Event Collector")
    print("Collects Security/System/Application logs from network PCs")
    print("="*70)
    
    collector = RemoteWindowsEventCollector()
    collector.collect_all()

if __name__ == '__main__':
    main()
