# -*- coding: utf-8 -*-
"""
JFS SIEM - Agent Collector Server
Receives event logs from remote agents and stores in database

USAGE:
1. Run this on collector PC: python agent_collector_server.py
2. Run agent on remote PC: python jfs_agent.py --server <collector_ip>
3. Events will be automatically stored in database
"""

import sys
import os
import socket
import json
import threading
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.database_manager import DatabaseManager
from common.logger import get_logger

logger = get_logger('agent_collector_server')
db = DatabaseManager()

class AgentCollectorServer:
    def __init__(self, host='0.0.0.0', port=9999):
        """Initialize server"""
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.total_events = 0
        self.connected_agents = {}
        
        # Test database connection
        if not db.test_connection():
            print("✗ Database connection failed")
            sys.exit(1)
        print("✓ Database connected")
    
    def start(self):
        """Start the server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print("\n" + "="*70)
            print("JFS SIEM - Agent Collector Server")
            print("="*70)
            print(f"✓ Server listening on {self.host}:{self.port}")
            print(f"✓ Waiting for agent connections...")
            print(f"{'='*70}\n")
            
            logger.info(f"Agent collector server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"\n✓ New connection from {client_address[0]}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    print("\n\n✓ Shutting down server...")
                    self.running = False
                    break
                except Exception as e:
                    print(f"✗ Error accepting connection: {e}")
                    continue
        
        except Exception as e:
            print(f"✗ Server error: {e}")
            logger.error(f"Server error: {e}")
        
        finally:
            self.stop()
    
    def handle_client(self, client_socket, client_address):
        """Handle client connection"""
        client_ip = client_address[0]
        agent_name = "Unknown"
        events_received = 0
        
        try:
            # Set socket to non-blocking mode to keep connection open
            client_socket.setblocking(False)
            
            # Receive events from agent
            buffer = ""
            while True:
                try:
                    data = client_socket.recv(4096).decode('utf-8')
                    if not data:
                        # Empty data means connection closed by client
                        break
                    
                    buffer += data
                    
                    # Process complete JSON objects (delimited by newline)
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip():
                            try:
                                event_data = json.loads(line)
                                agent_name = event_data.get('agent', 'Unknown')
                                
                                # Store in database
                                if self.store_event(event_data):
                                    events_received += 1
                                    self.total_events += 1
                                    
                                    if events_received % 10 == 0:
                                        print(f"  [{agent_name}] Received {events_received} events...")
                                
                            except json.JSONDecodeError as e:
                                print(f"  ⚠ Invalid JSON: {str(e)[:50]}")
                                continue
                
                except BlockingIOError:
                    # No data available right now, that's OK - keep connection open
                    import time
                    time.sleep(0.1)
                    continue
                except Exception as e:
                    print(f"  ✗ Error receiving data: {e}")
                    break
        
        except Exception as e:
            print(f"✗ Error handling client: {e}")
        
        finally:
            client_socket.close()
            print(f"✓ [{agent_name}] Connection closed - {events_received} events received")
            logger.info(f"Agent {agent_name} ({client_ip}) sent {events_received} events")
            
            # Update connected agents
            if agent_name in self.connected_agents:
                del self.connected_agents[agent_name]
    
    def store_event(self, event_data):
        """Store event in database"""
        try:
            query = """
            INSERT INTO security_events 
            (timestamp, event_type, severity, source_ip, 
             process_name, raw_log, event_data, user_account)
            VALUES (%(timestamp)s, %(event_type)s, %(severity)s, %(source_ip)s, 
                    %(process_name)s, %(raw_log)s, %(event_data)s, %(user_account)s)
            """
            
            params = {
                'timestamp': event_data.get('timestamp'),
                'event_type': event_data.get('log_type', 'windows_event'),
                'severity': event_data.get('severity', 'info'),
                'source_ip': event_data.get('agent', 'unknown'),
                'process_name': event_data.get('source', 'unknown'),
                'raw_log': event_data.get('message', '')[:1000],
                'event_data': json.dumps(event_data),
                'user_account': event_data.get('agent', 'unknown')
            }
            
            db.execute_query(query, params)
            return True
        
        except Exception as e:
            print(f"  ✗ Database error: {str(e)[:100]}")
            logger.error(f"Database error: {e}")
            return False
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        print(f"\n{'='*70}")
        print(f"Server Statistics:")
        print(f"  Total events received: {self.total_events}")
        print(f"  Connected agents: {len(self.connected_agents)}")
        print(f"{'='*70}")

def main():
    server = AgentCollectorServer(host='0.0.0.0', port=9999)
    server.start()

if __name__ == '__main__':
    main()
