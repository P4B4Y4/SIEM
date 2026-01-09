#!/usr/bin/env python3
"""
Fortinet Syslog Listener - Windows Service
Runs as a Windows Service and continuously listens for Fortinet syslog messages
"""

import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import json
import re
from datetime import datetime
import mysql.connector
from pathlib import Path
import time

# Configuration
LISTEN_PORT = 514
LISTEN_IP = '0.0.0.0'
LOG_FILE = 'd:\\xamp\\htdocs\\SIEM\\logs\\fortinet-listener.log'
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = ''
DB_NAME = 'jfs_siem'

class FortinetListenerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "JFSFortinetListener"
    _svc_display_name_ = "JFS Fortinet Syslog Listener"
    _svc_description_ = "Listens on UDP port 514 for Fortinet FortiGate syslog messages"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        self.message_count = 0
        self.socket = None
        self.db = None
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running = False
        if self.socket:
            self.socket.close()
        if self.db:
            self.db.close()
    
    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, ''))
        self.log("=== Fortinet Syslog Listener Service Started ===")
        self.log(f"Port: {LISTEN_PORT}")
        self.log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            self.db = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME
            )
            self.log("✓ Database connected")
        except Exception as e:
            self.log(f"✗ Database connection failed: {e}")
            return
        
        self.start_listening()
    
    def log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        msg = f"[{timestamp}] {message}"
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(msg + '\n')
        except:
            pass
        servicemanager.LogInfoMsg(msg)
    
    def start_listening(self):
        self.log("Creating UDP socket...")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(30)
            self.log("✓ Socket created")
            
            self.log(f"Binding to {LISTEN_IP}:{LISTEN_PORT}...")
            self.socket.bind((LISTEN_IP, LISTEN_PORT))
            self.log(f"✓ Listening on {LISTEN_IP}:{LISTEN_PORT}")
            self.log("Waiting for Fortinet syslog messages...")
            
            # Main listening loop
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    if data:
                        self.message_count += 1
                        self.process_message(data.decode('utf-8', errors='ignore'), addr[0], addr[1])
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"✗ Error receiving message: {e}")
                    continue
        
        except Exception as e:
            self.log(f"✗ Failed to start listener: {e}")
        finally:
            if self.socket:
                self.socket.close()
            if self.db:
                self.db.close()
            self.log(f"Listener stopped after processing {self.message_count} messages")
    
    def process_message(self, message, from_ip, from_port):
        try:
            self.log(f"Received from {from_ip}:{from_port}")
            
            # Parse syslog message
            parsed = self.parse_syslog(message)
            
            # Store in database
            self.store_event(parsed, from_ip, message)
            
            self.log("  ✓ Stored in database")
        except Exception as e:
            self.log(f"  ✗ Error processing message: {e}")
    
    def parse_syslog(self, message):
        parsed = {
            'raw': message,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'severity': 'medium',
            'hostname': '',
            'content': message
        }
        
        # Extract priority (e.g., <134>)
        match = re.match(r'^<(\d+)>', message)
        if match:
            priority = int(match.group(1))
            severity = priority % 8
            
            severity_map = {
                0: 'critical',
                1: 'critical',
                2: 'critical',
                3: 'high',
                4: 'medium',
                5: 'medium',
                6: 'low',
                7: 'low'
            }
            
            parsed['severity'] = severity_map.get(severity, 'medium')
            message = message[len(match.group(0)):]
        
        # Extract timestamp
        match = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', message)
        if match:
            parsed['timestamp'] = match.group(1)
            message = message[len(match.group(0)):]
        
        # Extract hostname
        match = re.match(r'^(\S+)\s+', message)
        if match:
            parsed['hostname'] = match.group(1)
            message = message[len(match.group(0)):]
        
        parsed['content'] = message
        return parsed
    
    def store_event(self, parsed, from_ip, raw_message):
        try:
            event_type = 'Fortinet-Syslog'
            severity = parsed['severity']
            content = parsed['content']
            
            # Extract IPs from FortiGate message
            source_ip = None
            dest_ip = None
            source_port = None
            dest_port = None
            
            match = re.search(r'srcip=(\S+)', content)
            if match:
                source_ip = match.group(1)
            
            match = re.search(r'dstip=(\S+)', content)
            if match:
                dest_ip = match.group(1)
            
            match = re.search(r'srcport=(\d+)', content)
            if match:
                source_port = match.group(1)
            
            match = re.search(r'dstport=(\d+)', content)
            if match:
                dest_port = match.group(1)
            
            agent_id = 'FortiGate-192.168.1.99'
            
            # Try to insert with agent_id
            try:
                cursor = self.db.cursor()
                query = """
                    INSERT INTO security_events 
                    (event_type, severity, source_ip, dest_ip, source_port, dest_port, raw_log, agent_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(query, (
                    event_type,
                    severity,
                    source_ip,
                    dest_ip,
                    source_port,
                    dest_port,
                    raw_message,
                    agent_id
                ))
                self.db.commit()
                cursor.close()
            except mysql.connector.Error as e:
                # If foreign key fails, try without agent_id
                if 'foreign key constraint' in str(e):
                    self.log("  ⚠ Foreign key constraint, storing without agent_id")
                    cursor = self.db.cursor()
                    query = """
                        INSERT INTO security_events 
                        (event_type, severity, source_ip, dest_ip, source_port, dest_port, raw_log)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(query, (
                        event_type,
                        severity,
                        source_ip,
                        dest_ip,
                        source_port,
                        dest_port,
                        raw_message
                    ))
                    self.db.commit()
                    cursor.close()
                else:
                    raise
        
        except Exception as e:
            self.log(f"⚠ Database error: {e}")

def handle_args():
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(FortinetListenerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(FortinetListenerService)

if __name__ == '__main__':
    handle_args()
