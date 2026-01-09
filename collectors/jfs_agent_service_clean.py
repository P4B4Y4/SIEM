#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
JFS SIEM - Windows Service Agent (Clean Version)
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
        self.events_sent = 0
    
    def SvcStop(self):
        self.is_alive = False
        try:
            win32event.SetEvent(self.hWaitStop)
        except:
            pass
        logger.info("Service stop requested")
    
    def SvcDoRun(self):
        logger.info(f"Service starting (PC: {self.pc_name})")
        try:
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ''))
        except:
            pass
        
        try:
            collection_thread = threading.Thread(target=self.collect_events_loop, daemon=True)
            collection_thread.start()
            logger.info("Collection thread started")
            
            while self.is_alive:
                try:
                    rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 5000)
                    if rc == 0:
                        break
                except:
                    time.sleep(1)
        except Exception as e:
            logger.error(f"Service error: {e}")
        finally:
            self.is_alive = False
            logger.info("Service stopped")
    
    def collect_events_loop(self):
        cycle = 0
        while self.is_alive:
            cycle += 1
            try:
                if not self.socket:
                    self.connect_to_server()
                    if not self.socket:
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
            self.socket.connect((self.server_ip, self.server_port))
            logger.info(f"Connected to {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            logger.warning(f"Connection failed: {e}")
            self.socket = None
            return False

class SimpleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent")
        self.root.geometry("500x400")
        
        title = tk.Label(root, text="JFS SIEM Agent", font=("Arial", 16, "bold"))
        title.pack(pady=15)
        
        config_frame = tk.LabelFrame(root, text="Configuration", font=("Arial", 11, "bold"), padx=15, pady=10)
        config_frame.pack(padx=20, pady=10, fill=tk.X)
        
        tk.Label(config_frame, text="Collector IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_entry = tk.Entry(config_frame, width=30, font=("Arial", 10))
        self.ip_entry.insert(0, "192.168.1.100")
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        tk.Label(config_frame, text="Collector Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(config_frame, width=30, font=("Arial", 10))
        self.port_entry.insert(0, "9999")
        self.port_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="Install Service", command=self.install_service, width=18, bg="green", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Start Service", command=self.start_service, width=18, bg="blue", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Stop Service", command=self.stop_service, width=18, bg="orange", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Remove Service", command=self.remove_service, width=18, bg="red", fg="white").pack(pady=5)
    
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
    if len(sys.argv) > 1:
        win32serviceutil.HandleCommandLine(JFSAgentService)
    else:
        root = tk.Tk()
        app = SimpleGUI(root)
        root.mainloop()
