#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
JFS SIEM Agent - Fresh Build from Scratch
Minimal, clean implementation
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
import servicemanager

# ============================================================================
# LOGGING SETUP
# ============================================================================
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

# ============================================================================
# WINDOWS SERVICE CLASS
# ============================================================================
class JFSAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "JFSSIEMAgent"
    _svc_display_name_ = "JFS SIEM Agent Service"
    _svc_description_ = "Collects Windows security events"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        config_file = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            'JFS_SIEM_Agent',
            'agent_config.json'
        )
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.server_ip = config.get('collector_ip', '192.168.1.100')
                    self.server_port = config.get('collector_port', 9999)
            except:
                self.server_ip = '192.168.1.100'
                self.server_port = 9999
        else:
            self.server_ip = '192.168.1.100'
            self.server_port = 9999
        
        self.pc_name = socket.gethostname()
        self.socket = None
    
    def SvcStop(self):
        """Stop the service"""
        logger.info("SvcStop() called")
        self.is_alive = False
        try:
            win32event.SetEvent(self.hWaitStop)
        except:
            pass
    
    def SvcDoRun(self):
        """Main service run method"""
        logger.info("="*70)
        logger.info("SvcDoRun() STARTED - Service is running")
        logger.info("="*70)
        
        try:
            # Start background thread for collection
            thread = threading.Thread(target=self.run_collection, daemon=True)
            thread.start()
            logger.info("Collection thread started")
            
            # Main loop - wait for stop event
            while self.is_alive:
                rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 500)
                if rc == 0:
                    logger.info("Stop event received")
                    break
        except Exception as e:
            logger.error(f"Service error: {e}", exc_info=True)
        finally:
            self.is_alive = False
            logger.info("Service stopped")
    
    def run_collection(self):
        """Background collection loop"""
        logger.info("Collection loop started")
        while self.is_alive:
            try:
                if not self.socket:
                    self.connect()
                time.sleep(10)
            except Exception as e:
                logger.error(f"Collection error: {e}")
                self.socket = None
                time.sleep(10)
    
    def connect(self):
        """Connect to collector"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(2)
            self.socket.connect((self.server_ip, self.server_port))
            self.socket.settimeout(None)
            logger.info(f"Connected to {self.server_ip}:{self.server_port}")
        except Exception as e:
            logger.warning(f"Connection failed: {e}")
            self.socket = None

# ============================================================================
# GUI CLASS
# ============================================================================
class AgentGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent")
        self.root.geometry("500x350")
        self.root.lift()
        
        # Title
        tk.Label(root, text="JFS SIEM Agent", font=("Arial", 16, "bold")).pack(pady=15)
        
        # Config frame
        frame = tk.LabelFrame(root, text="Configuration", font=("Arial", 11, "bold"), padx=15, pady=10)
        frame.pack(padx=20, pady=10, fill=tk.X)
        
        tk.Label(frame, text="Collector IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip = tk.Entry(frame, width=30)
        self.ip.insert(0, "192.168.1.100")
        self.ip.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        tk.Label(frame, text="Collector Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port = tk.Entry(frame, width=30)
        self.port.insert(0, "9999")
        self.port.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="Test Connection", command=self.test_conn, width=18, bg="purple", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Install Service", command=self.install, width=18, bg="green", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Start Service", command=self.start, width=18, bg="blue", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Stop Service", command=self.stop, width=18, bg="orange", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Remove Service", command=self.remove, width=18, bg="red", fg="white").pack(pady=5)
    
    def test_conn(self):
        """Test connection to collector"""
        try:
            ip = self.ip.get()
            port = int(self.port.get())
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.close()
            
            messagebox.showinfo("Success", f"✓ Connected to {ip}:{port}")
            logger.info(f"Connection test successful: {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            logger.error(f"Connection test failed: {e}")
    
    def install(self):
        """Install service"""
        try:
            ip = self.ip.get()
            port = int(self.port.get())
            
            # Save config
            config_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'JFS_SIEM_Agent')
            os.makedirs(config_dir, exist_ok=True)
            
            with open(os.path.join(config_dir, 'agent_config.json'), 'w') as f:
                json.dump({'collector_ip': ip, 'collector_port': port}, f, indent=2)
            
            # Install service
            win32serviceutil.InstallService(
                "__main__.JFSAgentService",
                JFSAgentService._svc_name_,
                JFSAgentService._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START
            )
            
            messagebox.showinfo("Success", f"Service installed!\nCollector: {ip}:{port}")
            logger.info(f"Service installed: {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Error", f"Install failed: {e}")
            logger.error(f"Install failed: {e}")
    
    def start(self):
        """Start service"""
        try:
            win32serviceutil.StartService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service started!")
            logger.info("Service started")
        except Exception as e:
            messagebox.showerror("Error", f"Start failed: {e}")
    
    def stop(self):
        """Stop service"""
        try:
            win32serviceutil.StopService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service stopped!")
            logger.info("Service stopped")
        except Exception as e:
            messagebox.showerror("Error", f"Stop failed: {e}")
    
    def remove(self):
        """Remove service"""
        try:
            win32serviceutil.RemoveService(JFSAgentService._svc_name_)
            messagebox.showinfo("Success", "Service removed!")
            logger.info("Service removed")
        except Exception as e:
            messagebox.showerror("Error", f"Remove failed: {e}")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
if __name__ == '__main__':
    logger.info("="*70)
    logger.info(f"Application started - argv: {sys.argv}")
    logger.info("="*70)
    
    if len(sys.argv) > 1:
        # Service command
        logger.info(f"Service mode: {sys.argv[1]}")
        win32serviceutil.HandleCommandLine(JFSAgentService)
    else:
        # GUI mode
        logger.info("GUI mode")
        try:
            root = tk.Tk()
            app = AgentGUI(root)
            root.mainloop()
        except Exception as e:
            logger.error(f"GUI error: {e}", exc_info=True)
            messagebox.showerror("Error", f"GUI failed: {e}")
