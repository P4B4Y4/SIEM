# -*- coding: utf-8 -*-
"""
JFS SIEM - Windows Service Agent
Runs as a Windows Service and maintains persistent connection to collector
Even if GUI is closed, the service continues collecting events
"""

import sys
import os
import json
import socket
import time
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32evtlog
import win32con
from datetime import datetime
import subprocess
import tempfile
import shutil
import sqlite3
import base64
import io

try:
    import psutil
except ImportError:
    psutil = None

try:
    from PIL import ImageGrab
except ImportError:
    ImageGrab = None

try:
    import winreg
except ImportError:
    winreg = None

try:
    import ctypes
except ImportError:
    ctypes = None

# Setup logging
log_dir = None
log_file = None

# Try multiple locations for log directory
log_locations = [
    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'JFS_SIEM_Agent', 'logs'),
    os.path.join(os.path.expanduser('~'), 'JFS_SIEM_Agent', 'logs'),
    os.path.join(os.path.dirname(__file__), 'logs'),
    os.path.join(os.environ.get('TEMP', '/tmp'), 'JFS_SIEM_Agent'),
]

for loc in log_locations:
    try:
        os.makedirs(loc, exist_ok=True)
        log_dir = loc
        log_file = os.path.join(loc, 'jfs_agent_service.log')
        break
    except:
        continue

# Setup logging with fallback
handlers = [logging.StreamHandler()]  # Always include console
if log_file:
    try:
        handlers.insert(0, logging.FileHandler(log_file))
    except:
        pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers
)

logger = logging.getLogger(__name__)
if log_file:
    logger.info(f"Logging to: {log_file}")
else:
    logger.info("No log file configured, using console only")

class JFSAgentService(win32serviceutil.ServiceFramework):
    """Windows Service for JFS SIEM Agent"""
    
    _svc_name_ = "JFSSIEMAgent"
    _svc_display_name_ = "JFS SIEM Agent Service"
    _svc_description_ = "Collects Windows security events and sends to SIEM collector"
    
    def __init__(self, args=None):
        logger.info("JFSAgentService.__init__ starting...")
        try:
            if args is None:
                args = []
            logger.info("Initializing ServiceFramework...")
            win32serviceutil.ServiceFramework.__init__(self, args)
            logger.info("ServiceFramework initialized")
            
            logger.info("Creating wait stop event...")
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            logger.info("Wait stop event created")
            
            self.is_alive = True
            logger.info("is_alive set to True")
            
            # Load configuration from file if it exists
            # Try multiple locations for config file
            config_file = None
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "agent_config.json"),
                os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'JFS_SIEM_Agent', 'agent_config.json'),
                "agent_config.json"
            ]
            
            logger.info(f"Looking for config file in {len(possible_paths)} locations...")
            for path in possible_paths:
                logger.debug(f"Checking: {path}")
                if os.path.exists(path):
                    config_file = path
                    logger.info(f"Found config file: {config_file}")
                    break
            
            if config_file:
                try:
                    logger.info(f"Loading configuration from {config_file}...")
                    with open(config_file, "r") as f:
                        config = json.load(f)
                        self.server_ip = config.get("collector_ip", "192.168.1.100")
                        self.server_port = config.get("collector_port", 9999)
                        logger.info(f"Loaded config: collector_ip={self.server_ip}, collector_port={self.server_port}")
                except Exception as e:
                    logger.error(f"Could not load config from {config_file}: {e}", exc_info=True)
                    logger.warning("Using default configuration")
                    self.server_ip = "192.168.1.100"
                    self.server_port = 9999
            else:
                # Use defaults if no config file
                logger.info("No config file found in any location, using defaults")
                self.server_ip = "192.168.1.100"
                self.server_port = 9999
            
            logger.info(f"Getting PC name...")
            self.pc_name = socket.gethostname()
            logger.info(f"PC name: {self.pc_name}")
            
            self.socket = None
            self.events_sent = 0
            self.last_record_numbers = {
                'System': 0,
                'Application': 0,
                'Security': 0
            }
            logger.info("JFSAgentService.__init__ completed successfully")
        except Exception as e:
            logger.error(f"FATAL ERROR in JFSAgentService.__init__: {e}", exc_info=True)
            raise
    
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
        logger.info(f"JFS SIEM Agent Service starting... (PC: {self.pc_name})")
        logger.info(f"Server config: {self.server_ip}:{self.server_port}")
        
        try:
            # Log service start
            try:
                logger.info("Attempting to log service start to Windows Event Log...")
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, '')
                )
                logger.info("Service start logged to Windows Event Log")
            except Exception as e:
                logger.warning(f"Could not log to Windows Event Log: {e}")
            
            # Start collection in a separate thread (daemon so it doesn't block service stop)
            try:
                logger.info("Creating collection thread...")
                collection_thread = threading.Thread(target=self.collect_events_loop, daemon=True)
                collection_thread.daemon = True
                logger.info("Starting collection thread...")
                collection_thread.start()
                logger.info("Collection thread started successfully")
            except Exception as e:
                logger.error(f"Failed to start collection thread: {e}", exc_info=True)
                raise
            
            # Main service loop - wait for stop event
            logger.info("Entering main service loop")
            loop_count = 0
            while self.is_alive:
                loop_count += 1
                try:
                    # Wait for stop event with 5 second timeout
                    logger.debug(f"Service loop iteration {loop_count}, waiting for stop event...")
                    rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 5000)
                    if rc == 0:
                        logger.info("Stop event received, exiting service loop")
                        break
                    # Log every 10 iterations to show service is alive
                    if loop_count % 10 == 0:
                        logger.info(f"Service running (loop {loop_count}), waiting for stop event...")
                except Exception as e:
                    logger.error(f"Wait error in loop iteration {loop_count}: {e}", exc_info=True)
                    time.sleep(1)
                    
        except Exception as e:
            logger.error(f"FATAL Service run error: {e}", exc_info=True)
            raise
        finally:
            # Cleanup
            logger.info("Service cleanup starting...")
            self.is_alive = False
            try:
                self.close_connection()
                logger.info("Connection closed")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
            logger.info("JFS SIEM Agent Service stopped")
    
    def connect_to_server(self):
        """Connect to collector server with retry logic"""
        max_retries = 3
        retry_delay = 2
        
        logger.info(f"connect_to_server() called, will attempt {max_retries} times")
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Connection attempt {attempt + 1}/{max_retries}: Creating socket...")
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                logger.info(f"Connection attempt {attempt + 1}/{max_retries}: Socket created, connecting to {self.server_ip}:{self.server_port}...")
                self.socket.connect((self.server_ip, self.server_port))
                logger.info(f"✓ Successfully connected to collector at {self.server_ip}:{self.server_port}")
                return True
            except socket.timeout as e:
                logger.warning(f"Connection attempt {attempt + 1}/{max_retries} TIMEOUT: {e}")
                self.socket = None
            except socket.gaierror as e:
                logger.warning(f"Connection attempt {attempt + 1}/{max_retries} DNS ERROR: {e}")
                self.socket = None
            except ConnectionRefusedError as e:
                logger.warning(f"Connection attempt {attempt + 1}/{max_retries} REFUSED (collector not listening): {e}")
                self.socket = None
            except OSError as e:
                logger.warning(f"Connection attempt {attempt + 1}/{max_retries} OS ERROR: {e}")
                self.socket = None
            except Exception as e:
                logger.error(f"Connection attempt {attempt + 1}/{max_retries} UNEXPECTED ERROR: {e}", exc_info=True)
                self.socket = None
            
            if attempt < max_retries - 1:
                logger.info(f"Waiting {retry_delay} seconds before retry...")
                time.sleep(retry_delay)
        
        logger.error(f"Failed to connect to {self.server_ip}:{self.server_port} after {max_retries} attempts")
        return False
    
    def send_event(self, event_data):
        """Send event to collector server"""
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
                        'event_type': 'windows_event',
                        'severity': self._get_severity(event.EventType),
                        'what_happened': f"Event {event_id} from {event.SourceName}",
                        'computer': self.pc_name
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
                        'event_type': 'system_event',
                        'severity': self._get_severity(event.EventType),
                        'what_happened': f"System event {event_id}",
                        'computer': self.pc_name
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
    
    def collect_application_events(self):
        """Collect Windows Application events"""
        try:
            hand = win32evtlog.OpenEventLog(None, 'Application')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            for event in events:
                if count >= 20:
                    break
                
                try:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.now().isoformat()
                    
                    event_data = {
                        'agent': self.pc_name,
                        'timestamp': timestamp,
                        'log_type': 'Application',
                        'event_id': event_id,
                        'source': event.SourceName,
                        'event_type': 'application_event',
                        'severity': self._get_severity(event.EventType),
                        'what_happened': f"Application event {event_id}",
                        'computer': self.pc_name
                    }
                    
                    if self.send_event(event_data):
                        count += 1
                except:
                    continue
            
            win32evtlog.CloseEventLog(hand)
            return count
        except Exception as e:
            logger.error(f"Error collecting application events: {e}")
            return 0
    
    def _get_severity(self, event_type):
        """Convert Windows event type to severity"""
        severity_map = {
            win32con.EVENTLOG_ERROR_TYPE: 'critical',
            win32con.EVENTLOG_WARNING_TYPE: 'warning',
            win32con.EVENTLOG_INFORMATION_TYPE: 'info',
            win32con.EVENTLOG_AUDIT_FAILURE: 'warning',
            win32con.EVENTLOG_AUDIT_SUCCESS: 'info'
        }
        return severity_map.get(event_type, 'info')
    
    def collect_events_loop(self):
        """Main collection loop - runs continuously"""
        cycle = 0
        logger.info("Event collection loop started")
        logger.info(f"Will attempt to connect to {self.server_ip}:{self.server_port}")
        
        while self.is_alive:
            cycle += 1
            
            try:
                # Reconnect if needed
                if not self.socket:
                    logger.info(f"[Cycle {cycle}] Socket not connected, attempting to connect to collector at {self.server_ip}:{self.server_port}...")
                    try:
                        if not self.connect_to_server():
                            logger.warning(f"[Cycle {cycle}] Could not connect to collector, will retry in 10 seconds")
                            time.sleep(10)
                            continue
                    except Exception as conn_error:
                        logger.error(f"[Cycle {cycle}] Connection error: {conn_error}", exc_info=True)
                        time.sleep(10)
                        continue
                
                logger.info(f"[Cycle {cycle}] Starting event collection...")
                
                try:
                    # Collect from all log types
                    logger.debug(f"[Cycle {cycle}] Collecting security events...")
                    security_count = self.collect_security_events()
                    logger.debug(f"[Cycle {cycle}] Collected {security_count} security events")
                    
                    logger.debug(f"[Cycle {cycle}] Collecting system events...")
                    system_count = self.collect_system_events()
                    logger.debug(f"[Cycle {cycle}] Collected {system_count} system events")
                    
                    logger.debug(f"[Cycle {cycle}] Collecting application events...")
                    app_count = self.collect_application_events()
                    logger.debug(f"[Cycle {cycle}] Collected {app_count} application events")
                    
                    total_this_cycle = security_count + system_count + app_count
                    logger.info(f"[Cycle {cycle}] Collected {total_this_cycle} events (Security: {security_count}, System: {system_count}, App: {app_count})")
                    logger.info(f"Total events sent so far: {self.events_sent}")
                except Exception as collect_error:
                    logger.error(f"[Cycle {cycle}] Error during event collection: {collect_error}", exc_info=True)
                    self.socket = None
                
            except Exception as e:
                logger.error(f"[Cycle {cycle}] Unexpected error in collection cycle: {e}", exc_info=True)
                self.socket = None
            
            # Wait 10 seconds before next cycle
            logger.debug(f"[Cycle {cycle}] Waiting 10 seconds before next cycle...")
            time.sleep(10)
    
    def close_connection(self):
        """Close socket connection"""
        try:
            if self.socket:
                self.socket.close()
                logger.info("Socket closed")
        except:
            pass

class SimpleGUI:
    """Simple GUI for service management"""
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent - Service Manager")
        self.root.geometry("600x550")
        
        # Title
        title = tk.Label(root, text="JFS SIEM Agent", font=("Arial", 16, "bold"))
        title.pack(pady=15)
        
        # Configuration Frame
        config_frame = tk.LabelFrame(root, text="Configuration", font=("Arial", 11, "bold"), padx=15, pady=10)
        config_frame.pack(padx=20, pady=10, fill=tk.X)
        
        # Collector IP
        tk.Label(config_frame, text="Collector IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_entry = tk.Entry(config_frame, width=30, font=("Arial", 10))
        self.ip_entry.insert(0, "192.168.1.100")
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Collector Port
        tk.Label(config_frame, text="Collector Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(config_frame, width=30, font=("Arial", 10))
        self.port_entry.insert(0, "9999")
        self.port_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # PC Name
        tk.Label(config_frame, text="PC Name:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.name_entry = tk.Entry(config_frame, width=30, font=("Arial", 10))
        self.name_entry.insert(0, socket.gethostname())
        self.name_entry.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Status
        status_frame = tk.LabelFrame(root, text="Service Status", font=("Arial", 11, "bold"), padx=15, pady=10)
        status_frame.pack(padx=20, pady=10, fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Not Installed", fg="red", font=("Arial", 11, "bold"))
        self.status_label.pack(pady=10)
        
        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="Install Service", command=self.install_service, 
                 width=18, bg="green", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(btn_frame, text="Start Service", command=self.start_service, 
                 width=18, bg="blue", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(btn_frame, text="Stop Service", command=self.stop_service, 
                 width=18, bg="orange", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(btn_frame, text="Remove Service", command=self.remove_service, 
                 width=18, bg="red", fg="white", font=("Arial", 10)).pack(pady=5)
        
        # Info
        info = tk.Label(root, text="Service will run continuously 24/7\neven after closing this window", 
                       font=("Arial", 9), fg="gray")
        info.pack(pady=10)
    
    def install_service(self):
        try:
            # Get values from GUI
            collector_ip = self.ip_entry.get()
            collector_port = self.port_entry.get()
            
            # Validate inputs
            if not collector_ip:
                messagebox.showerror("Error", "Please enter Collector IP")
                return
            if not collector_port:
                messagebox.showerror("Error", "Please enter Collector Port")
                return
            
            try:
                port = int(collector_port)
            except ValueError:
                messagebox.showerror("Error", "Port must be a number")
                return
            
            # Save configuration to file
            config = {
                "collector_ip": str(collector_ip),
                "collector_port": int(port)
            }
            
            # Try to save to APPDATA first, fallback to script directory
            try:
                config_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'JFS_SIEM_Agent')
                os.makedirs(config_dir, exist_ok=True)
                config_file = os.path.join(config_dir, "agent_config.json")
            except:
                config_file = os.path.join(os.path.dirname(__file__), "agent_config.json")
            
            try:
                with open(config_file, "w") as f:
                    json.dump(config, f, indent=2)
                logger.info(f"Configuration saved to {config_file}")
            except Exception as e:
                logger.error(f"Failed to save config: {e}")
                messagebox.showerror("Error", f"Failed to save configuration: {e}")
                return
            
            # Check if service already exists and remove it
            try:
                # Stop the service first
                try:
                    win32serviceutil.StopService(JFSAgentService._svc_name_)
                    logger.info("Stopped old service")
                    time.sleep(2)  # Wait for service to stop
                except:
                    pass
                
                # Now remove it
                win32serviceutil.RemoveService(JFSAgentService._svc_name_)
                logger.info("Removed old service")
                time.sleep(1)  # Wait for removal to complete
            except Exception as e:
                logger.warning(f"Could not remove old service: {e}")
            
            # Install service
            try:
                # Use the correct module path for the service
                # When running as EXE, __name__ will be '__main__'
                if __name__ == '__main__':
                    # Running as EXE - use the module name from the EXE
                    python_class_string = "__main__.JFSAgentService"
                else:
                    # Running as script
                    python_class_string = f"{__name__}.JFSAgentService"
                
                logger.info(f"Installing service with class string: {python_class_string}")
                
                win32serviceutil.InstallService(
                    python_class_string,
                    JFSAgentService._svc_name_,
                    JFSAgentService._svc_display_name_,
                    startType=win32service.SERVICE_AUTO_START
                )
            except Exception as install_error:
                logger.error(f"InstallService error: {install_error}")
                # Try alternative method using command line
                import subprocess
                exe_path = os.path.abspath(__file__)
                result = subprocess.run([
                    sys.executable, exe_path, 'install'
                ], capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception(f"Service installation failed: {result.stderr}")
            messagebox.showinfo("Success", f"Service installed!\nCollector: {collector_ip}:{collector_port}")
            logger.info(f"Service installed with collector {collector_ip}:{collector_port}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to install: {e}")
    
    def start_service(self):
        try:
            win32serviceutil.StartService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service started!")
            logger.info("Service started")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start: {e}")
    
    def stop_service(self):
        try:
            win32serviceutil.StopService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service stopped!")
            logger.info("Service stopped")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop: {e}")
    
    def remove_service(self):
        try:
            win32serviceutil.RemoveService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service removed!")
            logger.info("Service removed")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove: {e}")

def handle_command_line(argv):
    """Handle command line arguments"""
    if len(argv) > 1:
        if argv[1] == 'install':
            try:
                # Use the correct module path for the service
                if __name__ == '__main__':
                    python_class_string = "__main__.JFSAgentService"
                else:
                    python_class_string = f"{__name__}.JFSAgentService"
                
                logger.info(f"Installing service with class string: {python_class_string}")
                
                win32serviceutil.InstallService(
                    python_class_string,
                    JFSAgentService._svc_name_,
                    JFSAgentService._svc_display_name_,
                    startType=win32service.SERVICE_AUTO_START
                )
                logger.info("Service installed successfully")
            except Exception as e:
                logger.error(f"Failed to install service: {e}")
                sys.exit(1)
        elif argv[1] == 'remove':
            try:
                win32serviceutil.RemoveService(JFSAgentService._svc_name_)
                logger.info("Service removed successfully")
            except Exception as e:
                logger.error(f"Failed to remove service: {e}")
                sys.exit(1)
        elif argv[1] == 'start':
            try:
                win32serviceutil.StartService(JFSAgentService._svc_name_)
                logger.info("Service started")
            except Exception as e:
                logger.error(f"Failed to start service: {e}")
                sys.exit(1)
        elif argv[1] == 'stop':
            try:
                win32serviceutil.StopService(JFSAgentService._svc_name_)
                logger.info("Service stopped")
            except Exception as e:
                logger.error(f"Failed to stop service: {e}")
                sys.exit(1)
        else:
            print("Usage: jfs_agent_service.py [install|remove|start|stop]")
    else:
        # Show GUI when run without arguments
        try:
            root = tk.Tk()
            app = SimpleGUI(root)
            logger.info("GUI started successfully")
            root.mainloop()
        except Exception as e:
            logger.error(f"GUI Error: {e}", exc_info=True)
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    logger.info("="*70)
    logger.info("JFS SIEM Agent starting")
    logger.info(f"sys.argv: {sys.argv}")
    logger.info("="*70)
    
    try:
        # Always try to handle as command line first
        handle_command_line(sys.argv)
    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
