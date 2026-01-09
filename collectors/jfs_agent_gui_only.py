#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
JFS SIEM Agent - GUI with Service Features
"""
import sys
import os
import json
import socket
import time
import logging
import threading
import tkinter as tk
from tkinter import messagebox
import win32serviceutil
import win32service
import win32event
import win32api
import servicemanager
import win32evtlog
import win32con
from datetime import datetime

# Setup logging
log_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'JFS_SIEM_Agent', 'logs')
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
    _svc_name_ = "JFSSIEMAgent"
    _svc_display_name_ = "JFS SIEM Agent Service"
    _svc_description_ = "Collects Windows security events"
    
    def __init__(self, args=None):
        if args is None:
            args = []
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True
        
        # Load config
        config_file = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'JFS_SIEM_Agent', 'agent_config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, "r") as f:
                    config = json.load(f)
                    self.server_ip = config.get("collector_ip", "192.168.1.100")
                    self.server_port = config.get("collector_port", 9999)
            except:
                self.server_ip = "192.168.1.100"
                self.server_port = 9999
        else:
            self.server_ip = "192.168.1.100"
            self.server_port = 9999
        
        self.pc_name = socket.gethostname()
        self.socket = None
    
    def SvcStop(self):
        self.is_alive = False
        try:
            win32event.SetEvent(self.hWaitStop)
        except:
            pass
        logger.info("Service stop requested")
    
    def SvcDoRun(self):
        logger.info("="*70)
        logger.info("SvcDoRun() CALLED - Service startup beginning")
        logger.info("="*70)
        logger.info(f"Service starting (PC: {self.pc_name})")
        logger.info(f"Server config: {self.server_ip}:{self.server_port}")
        
        # Start collection thread IMMEDIATELY in background (daemon, non-blocking)
        logger.info("STEP 1: Creating collection thread...")
        try:
            collection_thread = threading.Thread(target=self.collect_events_loop, daemon=True)
            collection_thread.daemon = True
            logger.info("STEP 1: Thread created, starting...")
            collection_thread.start()
            logger.info("STEP 1: Collection thread started successfully")
        except Exception as e:
            logger.error(f"STEP 1 FAILED: Could not start collection thread: {e}", exc_info=True)
        
        # Log to Windows Event Log
        logger.info("STEP 2: Logging to Windows Event Log...")
        try:
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ''))
            logger.info("STEP 2: Logged to Windows Event Log successfully")
        except Exception as e:
            logger.warning(f"STEP 2 WARNING: Could not log to Event Log: {e}")
        
        # Main service loop - just wait for stop event
        # This loop keeps the service alive and responsive to Windows
        logger.info("STEP 3: Entering main service loop...")
        logger.info("Service is now running and ready")
        try:
            loop_count = 0
            while self.is_alive:
                loop_count += 1
                try:
                    # Wait for stop event with 500ms timeout (very responsive)
                    rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 500)
                    if rc == 0:
                        logger.info(f"STEP 3: Stop event received after {loop_count} iterations")
                        break
                    if loop_count % 20 == 0:
                        logger.info(f"STEP 3: Service loop running (iteration {loop_count})")
                except Exception as e:
                    logger.error(f"STEP 3 ERROR in wait: {e}", exc_info=True)
                    time.sleep(0.5)
        except Exception as e:
            logger.error(f"STEP 3 FATAL: Service error: {e}", exc_info=True)
        finally:
            logger.info("STEP 4: Service cleanup starting...")
            self.is_alive = False
            logger.info("Service stopped")
    
    def collect_events_loop(self):
        cycle = 0
        logger.info("Collection loop started")
        
        while self.is_alive:
            cycle += 1
            try:
                if not self.socket:
                    logger.info(f"[Cycle {cycle}] Attempting connection...")
                    self.connect_to_server()
                    if not self.socket:
                        logger.info(f"[Cycle {cycle}] Connection failed, will retry in 10 seconds")
                        time.sleep(10)
                        continue
                
                logger.info(f"[Cycle {cycle}] Collecting events...")
                time.sleep(10)
            except Exception as e:
                logger.error(f"Collection error: {e}")
                self.socket = None
                time.sleep(10)
    
    def connect_to_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set socket timeout to 2 seconds (don't wait forever)
            self.socket.settimeout(2)
            self.socket.connect((self.server_ip, self.server_port))
            # Remove timeout after connection
            self.socket.settimeout(None)
            logger.info(f"Connected to {self.server_ip}:{self.server_port}")
            return True
        except socket.timeout:
            logger.warning(f"Connection timeout to {self.server_ip}:{self.server_port}")
            self.socket = None
            return False
        except Exception as e:
            logger.warning(f"Connection failed: {e}")
            self.socket = None
            return False

class SimpleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent")
        self.root.geometry("500x400")
        
        # Force window to be visible and on top
        self.root.lift()
        self.root.attributes('-topmost', True)
        self.root.after_idle(self.root.attributes, '-topmost', False)
        
        # Title
        title = tk.Label(root, text="JFS SIEM Agent", font=("Arial", 16, "bold"))
        title.pack(pady=15)
        
        # Config frame
        config_frame = tk.LabelFrame(root, text="Configuration", font=("Arial", 11, "bold"), padx=15, pady=10)
        config_frame.pack(padx=20, pady=10, fill=tk.X)
        
        # IP
        tk.Label(config_frame, text="Collector IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_entry = tk.Entry(config_frame, width=30, font=("Arial", 10))
        self.ip_entry.insert(0, "192.168.1.100")
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Port
        tk.Label(config_frame, text="Collector Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(config_frame, width=30, font=("Arial", 10))
        self.port_entry.insert(0, "9999")
        self.port_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="Test Connection", command=self.test_connection, width=18, bg="purple", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Install Service", command=self.install_service, width=18, bg="green", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Start Service", command=self.start_service, width=18, bg="blue", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Stop Service", command=self.stop_service, width=18, bg="orange", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Remove Service", command=self.remove_service, width=18, bg="red", fg="white").pack(pady=5)
    
    def test_connection(self):
        """Test if collector is listening"""
        try:
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())
            
            logger.info(f"Testing connection to {ip}:{port}...")
            
            # Create a test socket
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(3)  # 3 second timeout
            
            try:
                test_socket.connect((ip, port))
                test_socket.close()
                messagebox.showinfo("Success", f"✓ Collector is listening!\n\nConnected to {ip}:{port}")
                logger.info(f"Connection test successful: {ip}:{port}")
            except socket.timeout:
                messagebox.showwarning("Timeout", f"✗ Connection timeout!\n\nCould not reach {ip}:{port}\n(Timeout after 3 seconds)")
                logger.warning(f"Connection test timeout: {ip}:{port}")
            except ConnectionRefusedError:
                messagebox.showwarning("Connection Refused", f"✗ Collector not listening!\n\n{ip}:{port} refused connection\n\nMake sure collector is running on that port")
                logger.warning(f"Connection refused: {ip}:{port}")
            except socket.gaierror:
                messagebox.showerror("DNS Error", f"✗ Cannot resolve hostname!\n\n'{ip}' is not a valid IP or hostname")
                logger.error(f"DNS error: {ip}")
            except Exception as e:
                messagebox.showerror("Error", f"✗ Connection failed!\n\n{e}")
                logger.error(f"Connection test error: {e}")
        except ValueError:
            messagebox.showerror("Error", "Port must be a number!")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")
            logger.error(f"Test connection error: {e}")
    
    def install_service(self):
        try:
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())
            
            config_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'JFS_SIEM_Agent')
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "agent_config.json")
            
            with open(config_file, "w") as f:
                json.dump({"collector_ip": ip, "collector_port": port}, f, indent=2)
            
            win32serviceutil.InstallService(
                "__main__.JFSAgentService",
                JFSAgentService._svc_name_,
                JFSAgentService._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START
            )
            messagebox.showinfo("Success", f"Service installed!\nCollector: {ip}:{port}")
            logger.info(f"Service installed with collector {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")
            logger.error(f"Install error: {e}")
    
    def start_service(self):
        try:
            win32serviceutil.StartService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service started!")
            logger.info("Service started")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")
    
    def stop_service(self):
        try:
            win32serviceutil.StopService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service stopped!")
            logger.info("Service stopped")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")
    
    def remove_service(self):
        try:
            win32serviceutil.RemoveService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service removed!")
            logger.info("Service removed")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")

if __name__ == '__main__':
    logger.info(f"="*70)
    logger.info(f"Main entry point - sys.argv: {sys.argv}")
    logger.info(f"="*70)
    
    try:
        # Check if running as a service
        # When Windows starts a service, it doesn't pass command-line args
        # So we need to check if we should run as service or GUI
        if len(sys.argv) > 1 and sys.argv[1] in ['install', 'remove', 'start', 'stop', 'debug']:
            logger.info(f"Running service command: {sys.argv[1]}")
            try:
                win32serviceutil.HandleCommandLine(JFSAgentService)
            except Exception as e:
                logger.error(f"Service command failed: {e}", exc_info=True)
                print(f"ERROR: {e}")
                import time
                time.sleep(5)
        else:
            # Try to run as service first (Windows will call us with no args if it's a service)
            # If we get here with no args, it could be either GUI or service startup
            logger.info("Attempting to run as service...")
            try:
                win32serviceutil.HandleCommandLine(JFSAgentService)
            except Exception as e:
                # If service handling fails, run GUI
                logger.info(f"Service handling failed ({type(e).__name__}: {e}), running GUI instead")
                print(f"Running GUI mode (service failed: {e})")
                root = tk.Tk()
                app = SimpleGUI(root)
                root.mainloop()
    except Exception as e:
        logger.error(f"FATAL ERROR in main: {e}", exc_info=True)
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        import time
        time.sleep(5)
