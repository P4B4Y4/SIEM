#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
JFS SIEM Agent - Simple Application (No Windows Service)
Just runs as a normal program that collects events
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

class Collector:
    def __init__(self):
        self.ip = "192.168.1.100"
        self.port = 9999
        self.socket = None
        self.is_running = False
        self.load_config()
    
    def load_config(self):
        cfg_file = os.path.join(os.path.dirname(__file__), "config.json")
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file) as f:
                    cfg = json.load(f)
                    self.ip = cfg.get("ip", "192.168.1.100")
                    self.port = cfg.get("port", 9999)
                    logger.info(f"Loaded config: {self.ip}:{self.port}")
            except Exception as e:
                logger.warning(f"Could not load config: {e}")
    
    def save_config(self):
        cfg_file = os.path.join(os.path.dirname(__file__), "config.json")
        try:
            with open(cfg_file, 'w') as f:
                json.dump({"ip": self.ip, "port": self.port}, f, indent=2)
            logger.info(f"Saved config: {self.ip}:{self.port}")
        except Exception as e:
            logger.error(f"Could not save config: {e}")
    
    def connect(self):
        try:
            self.socket = socket.socket()
            self.socket.settimeout(2)
            self.socket.connect((self.ip, self.port))
            self.socket.settimeout(None)
            logger.info(f"Connected to {self.ip}:{self.port}")
            return True
        except Exception as e:
            logger.warning(f"Connection failed: {e}")
            self.socket = None
            return False
    
    def start(self):
        self.is_running = True
        logger.info("Collector started")
        thread = threading.Thread(target=self.run_loop, daemon=True)
        thread.start()
    
    def stop(self):
        self.is_running = False
        logger.info("Collector stopped")
    
    def run_loop(self):
        import win32evtlog
        import win32con
        
        while self.is_running:
            try:
                if not self.socket:
                    if not self.connect():
                        time.sleep(5)
                        continue
                
                # Collect events from Security log
                try:
                    handle = win32evtlog.OpenEventLog(None, "Security")
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    
                    if events:
                        for event in events:
                            try:
                                event_data = {
                                    "source": event.GetSourceName(),
                                    "type": event.GetEventType(),
                                    "id": event.GetEventID(),
                                    "message": event.GetStringInserts(),
                                    "time": str(event.GetTime())
                                }
                                
                                # Send to collector
                                if self.socket:
                                    msg = json.dumps(event_data) + "\n"
                                    self.socket.sendall(msg.encode())
                                    logger.info(f"Sent event: {event_data['id']}")
                            except Exception as e:
                                logger.warning(f"Could not send event: {e}")
                    
                    win32evtlog.CloseEventLog(handle)
                except Exception as e:
                    logger.warning(f"Could not read events: {e}")
                
                time.sleep(10)
            except Exception as e:
                logger.error(f"Error: {e}")
                self.socket = None
                time.sleep(10)

class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JFS SIEM Agent")
        self.root.geometry("450x300")
        self.collector = Collector()
        
        tk.Label(root, text="JFS SIEM Agent", font=("Arial", 16, "bold")).pack(pady=15)
        
        # Status
        self.status = tk.Label(root, text="Status: Stopped", font=("Arial", 11), fg="red")
        self.status.pack(pady=5)
        
        # Config frame
        frame = tk.LabelFrame(root, text="Configuration", font=("Arial", 11, "bold"), padx=15, pady=10)
        frame.pack(padx=20, pady=10, fill=tk.X)
        
        tk.Label(frame, text="Collector IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip = tk.Entry(frame, width=30)
        self.ip.insert(0, self.collector.ip)
        self.ip.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        tk.Label(frame, text="Collector Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port = tk.Entry(frame, width=30)
        self.port.insert(0, str(self.collector.port))
        self.port.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="Test Connection", command=self.test, width=18, bg="purple", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Start Collecting", command=self.start, width=18, bg="green", fg="white").pack(pady=5)
        tk.Button(btn_frame, text="Stop Collecting", command=self.stop, width=18, bg="red", fg="white").pack(pady=5)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def test(self):
        try:
            ip = self.ip.get()
            port = int(self.port.get())
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.close()
            messagebox.showinfo("Success", f"Connected to {ip}:{port}")
            logger.info(f"Connection test OK: {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            logger.error(f"Connection test failed: {e}")
    
    def start(self):
        try:
            self.collector.ip = self.ip.get()
            self.collector.port = int(self.port.get())
            self.collector.save_config()
            self.collector.start()
            self.status.config(text="Status: Running", fg="green")
            messagebox.showinfo("Success", "Collector started")
            logger.info("Collector started from GUI")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def stop(self):
        self.collector.stop()
        self.status.config(text="Status: Stopped", fg="red")
        messagebox.showinfo("Success", "Collector stopped")
        logger.info("Collector stopped from GUI")
    
    def on_close(self):
        self.collector.stop()
        self.root.destroy()

if __name__ == '__main__':
    logger.info("JFS SIEM Agent started")
    root = tk.Tk()
    gui = GUI(root)
    root.mainloop()
    logger.info("JFS SIEM Agent closed")
