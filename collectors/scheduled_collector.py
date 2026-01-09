# -*- coding: utf-8 -*-
"""
JFS SIEM - Scheduled Windows Event Collector
Automatically collects events at regular intervals
"""

import sys
import os
import io
import time
import schedule
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Set UTF-8 encoding for stdout
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from common.config_manager import get_config_manager
from common.database_manager import DatabaseManager
from common.logger import get_logger

# Import the collector
from windows_events_remote import RemoteWindowsEventCollector

# Initialize components
config = get_config_manager()
logger = get_logger('scheduled_collector')
db = DatabaseManager()

def run_collection():
    """Run the collection task"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Starting scheduled collection...")
        logger.info("Starting scheduled collection")
        
        collector = RemoteWindowsEventCollector()
        total_events = collector.collect_all()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Collection completed. Total events: {total_events}")
        logger.info(f"Scheduled collection completed. Events collected: {total_events}")
        
    except Exception as e:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] ERROR: {str(e)}")
        logger.error(f"Scheduled collection failed: {str(e)}")

def main():
    """Main scheduler loop"""
    print("="*70)
    print("JFS SIEM - Scheduled Windows Event Collector")
    print("="*70)
    
    # Get collection interval from config (in minutes)
    remote_pcs_config = config.get_remote_pcs_config()
    interval_minutes = remote_pcs_config.get('collection_interval', 5)  # Default: 5 minutes
    
    print(f"\nCollection interval: {interval_minutes} minutes")
    print(f"Starting scheduler at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nPress Ctrl+C to stop the scheduler\n")
    
    logger.info(f"Scheduled collector started with interval: {interval_minutes} minutes")
    
    # Schedule the collection task
    schedule.every(interval_minutes).minutes.do(run_collection)
    
    # Run the scheduler
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nScheduler stopped by user")
        logger.info("Scheduled collector stopped by user")
        sys.exit(0)

if __name__ == '__main__':
    main()
