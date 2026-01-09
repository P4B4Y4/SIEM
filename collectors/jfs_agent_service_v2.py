#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
JFS SIEM Agent - Minimal Working Version
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

print("="*70)
print("JFS SIEM Agent v2 - Starting")
print("="*70)

# Wrap EVERYTHING in try/except to catch startup errors
try:
    import tkinter as tk
    from tkinter import messagebox
    
    # Show error dialog if anything goes wrong
    def show_error_and_exit(error_msg):
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("JFS SIEM Agent Error", f"Startup Error:\n\n{error_msg}")
            root.destroy()
        except:
            print(f"ERROR: {error_msg}")
        sys.exit(1)

except Exception as e:
    print(f"CRITICAL: Cannot import tkinter: {e}")
    import time
    time.sleep(5)  # Keep window open for 5 seconds
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    import json
    import socket
    import threading
    import time
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import win32evtlog
    import win32con
    
    print("All imports successful")
    
    class JFSAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "JFSSIEMAgent"
        _svc_display_name_ = "JFS SIEM Agent Service"
        _svc_description_ = "Collects Windows security events"
        
        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.is_alive = True
            self.server_ip = "192.168.1.100"
            self.server_port = 9999
            self.socket = None
            
        def SvcStop(self):
            self.is_alive = False
            try:
                win32event.SetEvent(self.hWaitStop)
            except:
                pass
                
        def SvcDoRun(self):
            print("Service running")
            while self.is_alive:
                try:
                    rc = win32event.WaitForMultipleObjects([self.hWaitStop], False, 5000)
                    if rc == 0:
                        break
                except:
                    time.sleep(1)
    
    class SimpleGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("JFS SIEM Agent")
            self.root.geometry("500x400")
            
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
            
            tk.Button(btn_frame, text="Install Service", command=self.install_service, 
                     width=18, bg="green", fg="white", font=("Arial", 10)).pack(pady=5)
            tk.Button(btn_frame, text="Start Service", command=self.start_service, 
                     width=18, bg="blue", fg="white", font=("Arial", 10)).pack(pady=5)
            tk.Button(btn_frame, text="Stop Service", command=self.stop_service, 
                     width=18, bg="orange", fg="white", font=("Arial", 10)).pack(pady=5)
            tk.Button(btn_frame, text="Remove Service", command=self.remove_service, 
                     width=18, bg="red", fg="white", font=("Arial", 10)).pack(pady=5)
        
        def install_service(self):
            try:
                ip = self.ip_entry.get()
                port = int(self.port_entry.get())
                
                # Save config
                config = {"collector_ip": ip, "collector_port": port}
                config_file = os.path.join(os.path.dirname(__file__), "agent_config.json")
                with open(config_file, "w") as f:
                    json.dump(config, f, indent=2)
                
                # Install service
                win32serviceutil.InstallService(
                    "__main__.JFSAgentService",
                    JFSAgentService._svc_name_,
                    JFSAgentService._svc_display_name_,
                    startType=win32service.SERVICE_AUTO_START
                )
                messagebox.showinfo("Success", f"Service installed!\nCollector: {ip}:{port}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to install: {e}")
        
        def start_service(self):
            try:
                win32serviceutil.StartService(JFSAgentService._svc_name_)
                messagebox.showinfo("Success", "Service started!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start: {e}")
        
        def stop_service(self):
            try:
                win32serviceutil.StopService(JFSAgentService._svc_name_)
                messagebox.showinfo("Success", "Service stopped!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop: {e}")
        
        def remove_service(self):
            try:
                win32serviceutil.RemoveService(JFSAgentService._svc_name_)
                messagebox.showinfo("Success", "Service removed!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove: {e}")
    
    if __name__ == '__main__':
        if len(sys.argv) > 1:
            win32serviceutil.HandleCommandLine(JFSAgentService)
        else:
            # Show GUI
            root = tk.Tk()
            app = SimpleGUI(root)
            root.mainloop()

except Exception as e:
    error_msg = f"{type(e).__name__}: {e}"
    print(f"ERROR: {error_msg}")
    import traceback
    traceback.print_exc()
    
    # Try to show error dialog
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("JFS SIEM Agent - Startup Error", f"Failed to start:\n\n{error_msg}\n\nCheck console for details.")
        root.destroy()
    except Exception as dialog_error:
        print(f"Could not show error dialog: {dialog_error}")
        import time
        time.sleep(5)  # Keep console open
    
    sys.exit(1)
