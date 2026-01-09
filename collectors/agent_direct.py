#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

# Logging
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'agent.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Agent(win32serviceutil.ServiceFramework):
    _svc_name_ = "JFSSIEMAgent"
    _svc_display_name_ = "JFS SIEM Agent"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True
        self.ip = "192.168.1.100"
        self.port = 9999
        self.load_config()
    
    def load_config(self):
        cfg_file = os.path.join(os.path.dirname(__file__), "config.json")
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file) as f:
                    cfg = json.load(f)
                    self.ip = cfg.get("ip", "192.168.1.100")
                    self.port = cfg.get("port", 9999)
            except:
                pass
    
    def SvcStop(self):
        logger.info("SvcStop called")
        self.is_alive = False
        try:
            win32event.SetEvent(self.hWaitStop)
        except:
            pass
    
    def SvcDoRun(self):
        logger.info("SvcDoRun called - SERVICE RUNNING")
        try:
            while self.is_alive:
                rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 1000)
                if rc == 0:
                    logger.info("Stop event received")
                    break
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            logger.info("Service exiting")

class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent")
        self.root.geometry("400x250")
        
        tk.Label(root, text="JFS SIEM Agent", font=("Arial", 14, "bold")).pack(pady=10)
        
        frame = tk.Frame(root)
        frame.pack(padx=20, pady=10)
        
        tk.Label(frame, text="IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip = tk.Entry(frame, width=25)
        self.ip.insert(0, "192.168.1.100")
        self.ip.grid(row=0, column=1)
        
        tk.Label(frame, text="Port:").grid(row=1, column=0, sticky=tk.W)
        self.port = tk.Entry(frame, width=25)
        self.port.insert(0, "9999")
        self.port.grid(row=1, column=1)
        
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Test", command=self.test, width=12).pack(pady=3)
        tk.Button(btn_frame, text="Install", command=self.install, width=12).pack(pady=3)
        tk.Button(btn_frame, text="Start Service", command=self.start, width=12).pack(pady=3)
        tk.Button(btn_frame, text="Stop Service", command=self.stop, width=12).pack(pady=3)
        tk.Button(btn_frame, text="Remove", command=self.remove, width=12).pack(pady=3)
    
    def test(self):
        try:
            ip = self.ip.get()
            port = int(self.port.get())
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.close()
            messagebox.showinfo("OK", f"Connected to {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def install(self):
        try:
            ip = self.ip.get()
            port = int(self.port.get())
            cfg_file = os.path.join(os.path.dirname(__file__), "config.json")
            with open(cfg_file, 'w') as f:
                json.dump({"ip": ip, "port": port}, f)
            
            # Use direct service installation
            win32serviceutil.InstallService(
                "__main__.Agent",
                Agent._svc_name_,
                Agent._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START
            )
            messagebox.showinfo("OK", "Service installed")
            logger.info(f"Installed: {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            logger.error(f"Install error: {e}")
    
    def start(self):
        try:
            logger.info("Starting service...")
            win32serviceutil.StartService(Agent._svc_name_)
            messagebox.showinfo("OK", "Service started")
            logger.info("Service started successfully")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            logger.error(f"Start error: {e}")
    
    def stop(self):
        try:
            win32serviceutil.StopService(Agent._svc_name_)
            messagebox.showinfo("OK", "Service stopped")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def remove(self):
        try:
            win32serviceutil.RemoveService(Agent._svc_name_)
            messagebox.showinfo("OK", "Service removed")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == '__main__':
    logger.info(f"Started with args: {sys.argv}")
    
    if len(sys.argv) > 1:
        logger.info(f"Service mode: {sys.argv[1]}")
        # Direct service handling
        if sys.argv[1] == 'install':
            win32serviceutil.InstallService(
                "__main__.Agent",
                Agent._svc_name_,
                Agent._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START
            )
        elif sys.argv[1] == 'remove':
            win32serviceutil.RemoveService(Agent._svc_name_)
        elif sys.argv[1] == 'start':
            win32serviceutil.StartService(Agent._svc_name_)
        elif sys.argv[1] == 'stop':
            win32serviceutil.StopService(Agent._svc_name_)
        else:
            win32serviceutil.HandleCommandLine(Agent)
    else:
        logger.info("GUI mode")
        root = tk.Tk()
        GUI(root)
        root.mainloop()
