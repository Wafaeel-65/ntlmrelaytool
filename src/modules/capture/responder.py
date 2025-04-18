import socket
import threading
import logging
import os
from datetime import datetime
from src.utils.db_handler import DatabaseHandler
from src.modules.storage.models import Plugin, Resultat

class ResponderCapture:
    def __init__(self, interface="0.0.0.0", port=8445):  # Changed to non-privileged port
        self.interface = interface
        self.port = port
        self.running = False
        self.sock = None
        self.db_handler = DatabaseHandler()
        self.logger = logging.getLogger(__name__)

    def start_listener(self):
        """Start the NTLM capture listener"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.interface, self.port))
            self.sock.listen(5)
            self.running = True
            self.logger.info(f"Listening on {self.interface}:{self.port}")
            
            while self.running:
                client, address = self.sock.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client, address)
                )
                client_handler.start()

        except Exception as e:
            self.logger.error(f"Error starting listener: {e}")
            self.stop_listener()

    def handle_client(self, client_socket, address):
        """Handle incoming client connections"""
        try:
            self.logger.info(f"Connection from {address[0]}:{address[1]}")
            
            # Receive NTLM challenge
            data = client_socket.recv(1024)
            if data:
                ntlm_hash = self.extract_ntlm_hash(data)
                if ntlm_hash:
                    # Store hash in database
                    self.store_capture(address[0], ntlm_hash)
                    
            client_socket.close()

        except Exception as e:
            self.logger.error(f"Error handling client {address}: {e}")
            if client_socket:
                client_socket.close()

    def extract_ntlm_hash(self, data):
        """Extract NTLM hash from captured data"""
        try:
            # Parse NTLM message and extract hash
            # This is a simplified example - real implementation would parse NTLM protocol
            ntlm_data = data.decode('utf-8', errors='ignore')
            if 'NTLMSSP' in ntlm_data:
                # Extract and return hash
                return ntlm_data
            return None

        except Exception as e:
            self.logger.error(f"Error extracting NTLM hash: {e}")
            return None

    def store_capture(self, source_ip, ntlm_hash):
        """Store captured hash in database"""
        try:
            # Create plugin record
            plugin_data = {
                'nom_plugin': 'NTLM Capture',
                'description': f'Captured from {source_ip}',
                'version': '1.0',
                'ntlm_key': ntlm_hash
            }
            plugin_id = self.db_handler.store_plugin(**plugin_data)

            # Store result
            if plugin_id:
                result_data = {
                    'id_plugin': plugin_id,
                    'status': 'SUCCESS',
                    'details': f'NTLM hash captured from {source_ip}'
                }
                self.db_handler.store_result(**result_data)

        except Exception as e:
            self.logger.error(f"Error storing capture: {e}")

    def stop_listener(self):
        """Stop the NTLM capture listener"""
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None
        self.logger.info("Listener stopped")