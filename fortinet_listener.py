#!/usr/bin/env python3
"""
Fortinet Syslog Listener for JFS SIEM
Listens on UDP port 514 for incoming syslog messages from FortiGate
Continuously receives and stores logs in the database
"""

import socket
import sys
import os
import json
import re
from datetime import datetime
import sqlite3
import mysql.connector
from pathlib import Path

# Configuration
LISTEN_PORT = 514
LISTEN_IP = '0.0.0.0'
LOG_FILE = 'd:\\xamp\\htdocs\\SIEM\\logs\\fortinet-listener.log'
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = ''
DB_NAME = 'jfs_siem'

class FortinetListener:
    def __init__(self):
        self.running = True
        self.message_count = 0
        self.log(f"=== Fortinet Syslog Listener Started ===")
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
            raise
    
    def log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        msg = f"[{timestamp}] {message}"
        print(msg)
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(msg + '\n')
        except:
            pass
    
    def start(self):
        self.log("Creating UDP socket...")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.log("✓ Socket created")
            
            self.log(f"Binding to {LISTEN_IP}:{LISTEN_PORT}...")
            self.socket.bind((LISTEN_IP, LISTEN_PORT))
            self.log(f"✓ Listening on {LISTEN_IP}:{LISTEN_PORT}")
            self.log("Waiting for Fortinet syslog messages...")
            self.log("Press Ctrl+C to stop\n")
            
            # Main listening loop
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    if data:
                        self.message_count += 1
                        self.process_message(data.decode('utf-8', errors='ignore'), addr[0], addr[1])
                except KeyboardInterrupt:
                    self.log("\nShutting down...")
                    break
                except Exception as e:
                    self.log(f"✗ Error receiving message: {e}")
                    continue
        
        except Exception as e:
            self.log(f"✗ Failed to start listener: {e}")
            raise
        finally:
            if hasattr(self, 'socket'):
                self.socket.close()
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
            
            agent_id = f'FortiGate-192.168.1.99'
            
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

if __name__ == '__main__':
    try:
        listener = FortinetListener()
        listener.start()
    except KeyboardInterrupt:
        print("\nShutdown requested")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to start listener: {e}")
        sys.exit(1)
