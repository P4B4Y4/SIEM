#!/usr/bin/env python3
"""
JFS-SIEM Windows Event Log Collector
Collects events from local Windows Event Logs (Security, System, Application)
PRODUCTION VERSION - FIXED: Correct DatabaseManager usage
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import win32evtlog
    import win32con
    import win32security
except ImportError:
    print("ERROR: pywin32 not installed. Run: pip install pywin32")
    sys.exit(1)

from datetime import datetime
import json
from common.config_manager import get_config_manager
from common.database_manager import DatabaseManager
from common.logger import get_logger
from common.path_manager import PathManager

# Initialize components
config = get_config_manager()
logger = get_logger('windows_events')
path_manager = PathManager()

# Get database configuration
db_config = config.get_database_config()

# Initialize database manager (NO ARGUMENTS - it's a singleton)
try:
    db = DatabaseManager()
    if db.test_connection():
        logger.info("Database connection established successfully")
    else:
        raise Exception("Database connection test failed")
except Exception as e:
    logger.error(f"Failed to connect to database: {e}")
    print(f"ERROR: Cannot connect to database. Check config/database.ini")
    print(f"Details: {e}")
    sys.exit(1)

def check_admin_privileges():
    """Check if running with administrator privileges"""
    try:
        return win32security.OpenProcessToken(win32security.GetCurrentProcess(), 
                                              win32con.TOKEN_QUERY)
    except Exception as e:
        logger.warning(f"Could not verify admin privileges: {e}")
        return False

def get_event_severity(event_type):
    """Map Windows event type to SIEM severity"""
    severity_map = {
        win32evtlog.EVENTLOG_ERROR_TYPE: 'high',
        win32evtlog.EVENTLOG_WARNING_TYPE: 'medium',
        win32evtlog.EVENTLOG_INFORMATION_TYPE: 'info',
        win32evtlog.EVENTLOG_AUDIT_FAILURE: 'high',
        win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'low'
    }
    return severity_map.get(event_type, 'info')

def get_siem_event_type(log_type, event_id, event_type):
    """Map Windows event to SIEM event type"""
    
    # Security log event IDs
    if log_type == 'Security':
        security_events = {
            4624: 'login',
            4625: 'failed_login',
            4634: 'logout',
            4648: 'explicit_login',
            4672: 'privilege_escalation',
            4720: 'user_created',
            4726: 'user_deleted',
            4728: 'user_added_to_group',
            4732: 'user_added_to_group',
            4756: 'user_added_to_group',
            4688: 'process_creation',
            4697: 'service_installed',
            5140: 'network_share_access',
            5156: 'firewall_connection'
        }
        return security_events.get(event_id, 'security_event')
    
    # System log events
    elif log_type == 'System':
        if event_type == win32evtlog.EVENTLOG_ERROR_TYPE:
            return 'system_error'
        elif event_type == win32evtlog.EVENTLOG_WARNING_TYPE:
            return 'system_warning'
        return 'system_event'
    
    # Application log events
    elif log_type == 'Application':
        if event_type == win32evtlog.EVENTLOG_ERROR_TYPE:
            return 'application_error'
        return 'application_event'
    
    return 'unknown'

def collect_events(log_type='Security', max_events=1000):
    """
    Collect events from specified Windows Event Log
    
    Args:
        log_type: 'Security', 'System', or 'Application'
        max_events: Maximum number of events to collect
    
    Returns:
        tuple: (events_collected, events_inserted)
    """
    logger.info(f"Starting collection from {log_type} log (max: {max_events} events)")
    
    # Check admin privileges for Security log
    if log_type == 'Security':
        if not check_admin_privileges():
            logger.warning("Security log requires administrator privileges")
            print("WARNING: Security log requires administrator privileges")
            print("Run this script as Administrator to collect Security events")
    
    events_collected = 0
    events_inserted = 0
    
    try:
        # Open event log
        hand = win32evtlog.OpenEventLog(None, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        events = True
        while events and events_collected < max_events:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                if events_collected >= max_events:
                    break
                
                events_collected += 1
                
                try:
                    # Extract event data
                    event_time = event.TimeGenerated.Format()
                    event_id = event.EventID & 0xFFFF  # Remove facility code
                    event_type_code = event.EventType
                    source = event.SourceName
                    computer = event.ComputerName
                    category = event.EventCategory
                    record_number = event.RecordNumber
                    
                    # Get event message
                    try:
                        message = win32evtlog.SafeFormatMessage(event, log_type)
                        if not message:
                            message = f"Event ID {event_id} from {source}"
                    except:
                        message = f"Event ID {event_id} from {source}"
                    
                    # Determine severity and event type
                    severity = get_event_severity(event_type_code)
                    siem_event_type = get_siem_event_type(log_type, event_id, event_type_code)
                    
                    # Build additional data
                    additional_data = {
                        'log_type': log_type,
                        'event_id': event_id,
                        'source': source,
                        'event_type': siem_event_type,
                        'computer': computer,
                        'category': category,
                        'record_number': record_number
                    }
                    
                    # Add string inserts if available
                    if event.StringInserts:
                        additional_data['string_inserts'] = event.StringInserts[:5]  # First 5 strings
                    
                    # Prepare data for insertion
                    query = """
                        INSERT INTO security_events 
                        (timestamp, event_type, severity, source_ip, event_data, raw_log)
                        VALUES (%(timestamp)s, %(event_type)s, %(severity)s, %(source_ip)s, %(event_data)s, %(raw_log)s)
                    """
                    
                    params = {
                        'timestamp': event_time,
                        'event_type': siem_event_type,
                        'severity': severity,
                        'source_ip': computer,
                        'event_data': json.dumps(additional_data),
                        'raw_log': message[:2000]
                    }
                    
                    # Insert into database
                    try:
                        db.execute_query(query, params)
                        events_inserted += 1
                    except Exception as e:
                        logger.warning(f"Failed to insert event {record_number}: {e}")
                    
                except Exception as e:
                    logger.warning(f"Error processing event {record_number}: {e}")
                    continue
        
        win32evtlog.CloseEventLog(hand)
        
        logger.info(f"Collection complete: {events_collected} collected, {events_inserted} inserted into database")
        print(f"\n{log_type} Log Collection Summary:")
        print(f"  Events Collected: {events_collected}")
        print(f"  Events Inserted:  {events_inserted}")
        
        return events_collected, events_inserted
        
    except Exception as e:
        logger.error(f"Error collecting from {log_type} log: {e}")
        print(f"ERROR: Failed to collect from {log_type} log: {e}")
        return 0, 0

def main():
    """Main execution function"""
    logger.info("=== Windows Event Log Collector Started ===")
    print("\n" + "="*60)
    print("JFS-SIEM Windows Event Log Collector")
    print("="*60)
    
    # Check admin privileges
    is_admin = check_admin_privileges()
    print(f"Administrator privileges: {'YES' if is_admin else 'NO'}")
    
    if not is_admin:
        print("\nWARNING: Not running as administrator")
        print("Security log collection may fail without admin privileges")
        print("Right-click Python/CMD and select 'Run as Administrator'\n")
    
    total_collected = 0
    total_inserted = 0
    
    # Collect from all three main logs
    log_types = ['System', 'Application', 'Security']
    
    for log_type in log_types:
        print(f"\nCollecting from {log_type} log...")
        collected, inserted = collect_events(log_type, max_events=500)
        total_collected += collected
        total_inserted += inserted
    
    # Final summary
    print("\n" + "="*60)
    print("FINAL SUMMARY")
    print("="*60)
    print(f"Total Events Collected: {total_collected}")
    print(f"Total Events Inserted:  {total_inserted}")
    print(f"Database: {db_config['host']}/{db_config['database']}")
    print("="*60)
    
    logger.info(f"=== Collection Complete: {total_collected} collected, {total_inserted} inserted ===")

if __name__ == "__main__":
    main()
