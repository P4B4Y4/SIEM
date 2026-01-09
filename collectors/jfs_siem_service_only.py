# -*- coding: utf-8 -*-
"""
JFS SIEM - Windows Service Agent (Service Only - No GUI)
Runs as a Windows Service and maintains persistent connection to collector
"""

import sys
import os
import json
import socket
import time
import logging
import threading
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32evtlog
import win32con
from datetime import datetime

# Setup logging
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'jfs_agent_service.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class JFSAgentService(win32serviceutil.ServiceFramework):
    """Windows Service for JFS SIEM Agent"""
    
    _svc_name_ = "JFSSIEMAgent"
    _svc_display_name_ = "JFS SIEM Agent Service"
    _svc_description_ = "Collects Windows security events and sends to SIEM collector"
    
    def __init__(self, args=None):
        if args is None:
            args = []
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True
        
        # Load configuration from file if it exists
        config_file = os.path.join(os.path.dirname(__file__), "agent_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
                    self.server_ip = config.get("collector_ip", "192.168.1.100")
                    self.server_port = config.get("collector_port", 9999)
                    logger.info(f"Loaded config: {self.server_ip}:{self.server_port}")
            except Exception as e:
                logger.warning(f"Could not load config: {e}, using defaults")
                self.server_ip = "192.168.1.100"
                self.server_port = 9999
        else:
            # Use defaults if no config file
            self.server_ip = "192.168.1.100"
            self.server_port = 9999
        
        self.pc_name = socket.gethostname()
        self.socket = None
        self.events_sent = 0
    
    def SvcStop(self):
        """Stop the service"""
        try:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        except:
            pass
        self.is_alive = False
        try:
            win32event.SetEvent(self.hWaitStop)
        except:
            pass
        self.close_connection()
        logger.info("Service stop requested")
    
    def SvcDoRun(self):
        """Run the service"""
        try:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
        except:
            pass
        
        logger.info(f"JFS SIEM Agent Service starting... (PC: {self.pc_name})")
        
        try:
            # Start collection in a separate thread
            collection_thread = threading.Thread(target=self.collect_events_loop, daemon=True)
            collection_thread.start()
            
            # Wait for stop event
            while self.is_alive:
                try:
                    rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 5000)
                    if rc == 0:
                        break
                except:
                    time.sleep(1)
        except Exception as e:
            logger.error(f"Service run error: {e}")
        finally:
            self.close_connection()
            logger.info("JFS SIEM Agent Service stopped")
    
    def connect_to_server(self):
        """Connect to collector server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            logger.info(f"Connected to collector at {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def send_event(self, event_data):
        """Send event to collector"""
        try:
            if not self.socket:
                return False
            json_data = json.dumps(event_data) + '\n'
            self.socket.sendall(json_data.encode('utf-8'))
            self.events_sent += 1
            return True
        except Exception as e:
            logger.error(f"Error sending event: {e}")
            self.socket = None
            return False
    
    def collect_security_events(self):
        """Collect Windows Security events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 50:
                    break
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': timestamp,
                        'log_type': 'Security',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'severity': 'info'
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except Exception as e:
            logger.error(f"Error collecting security events: {e}")
            return 0
    
    def collect_system_events(self):
        """Collect Windows System events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 30:
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
                        'severity': 'info'
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except Exception as e:
            logger.error(f"Error collecting system events: {e}")
            return 0
    
    def collect_events_loop(self):
        """Main collection loop"""
        cycle = 0
        
        while self.is_alive:
            cycle += 1
            
            # Reconnect if needed
            if not self.socket:
                if not self.connect_to_server():
                    time.sleep(10)
                    continue
            
            try:
                logger.info(f"[Cycle {cycle}] Starting event collection...")
                
                security_count = self.collect_security_events()
                system_count = self.collect_system_events()
                
                total = security_count + system_count
                logger.info(f"[Cycle {cycle}] Collected {total} events (Security: {security_count}, System: {system_count})")
                
                time.sleep(10)
            except Exception as e:
                logger.error(f"Collection error: {e}")
                time.sleep(5)
    
    def close_connection(self):
        """Close socket connection"""
        try:
            if self.socket:
                self.socket.close()
                logger.info("Socket closed")
        except:
            pass

def handle_command_line(argv):
    """Handle command line arguments"""
    if len(argv) > 1:
        if argv[1] == 'install':
            win32serviceutil.InstallService(
                JFSAgentService,
                JFSAgentService._svc_name_,
                JFSAgentService._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START
            )
            logger.info("Service installed")
        elif argv[1] == 'remove':
            win32serviceutil.RemoveService(JFSAgentService._svc_name_)
            logger.info("Service removed")
        elif argv[1] == 'start':
            win32serviceutil.StartService(JFSAgentService._svc_name_)
            logger.info("Service started")
        elif argv[1] == 'stop':
            win32serviceutil.StopService(JFSAgentService._svc_name_)
            logger.info("Service stopped")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        handle_command_line(sys.argv)
    else:
        servicemanager.Initialize()
        servicemanager.StartServiceCtrlDispatcher()

