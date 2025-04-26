import socket
import threading
import logging
import struct
import dns.resolver
from socketserver import ThreadingMixIn, UDPServer, BaseRequestHandler
from src.utils.db_handler import DatabaseHandler
from src.modules.storage.models import Plugin, Resultat

class ResponderCapture:
    def __init__(self, interface="0.0.0.0", poisoning_ports={'llmnr': 5355, 'nbt-ns': 137, 'mdns': 5353}):
        self.interface = interface
        self.poisoning_ports = poisoning_ports
        self.running = False
        self.servers = []
        self.db_handler = DatabaseHandler()
        self.logger = logging.getLogger(__name__)
        
    def start_poisoning(self):
        """Start all poisoning servers"""
        try:
            # Start LLMNR poisoning
            llmnr_server = LLMNRPoisoner((self.interface, self.poisoning_ports['llmnr']), self)
            llmnr_thread = threading.Thread(target=llmnr_server.serve_forever)
            llmnr_thread.daemon = True
            llmnr_thread.start()
            self.servers.append(llmnr_server)
            
            # Start NBT-NS poisoning
            nbtns_server = NBTNSPoisoner((self.interface, self.poisoning_ports['nbt-ns']), self)
            nbtns_thread = threading.Thread(target=nbtns_server.serve_forever)
            nbtns_thread.daemon = True
            nbtns_thread.start()
            self.servers.append(nbtns_server)
            
            # Start MDNS poisoning
            mdns_server = MDNSPoisoner((self.interface, self.poisoning_ports['mdns']), self)
            mdns_thread = threading.Thread(target=mdns_server.serve_forever)
            mdns_thread.daemon = True
            mdns_thread.start()
            self.servers.append(mdns_server)
            
            self.running = True
            self.logger.info(f"Poisoning servers started on {self.interface}")
            
        except Exception as e:
            self.logger.error(f"Error starting poisoning servers: {e}")
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

class LLMNRRequestHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        if data[2:4] == b'\x00\x00':  # Query packet
            name_length = struct.unpack('!B', data[12:13])[0]
            requested_name = data[13:13 + name_length].decode('utf-8')
            self.server.responder.handle_poisoned_request('LLMNR', self.client_address[0], requested_name)
            
class NBTNSRequestHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        if data[2:4] == b'\x01\x10':  # Name query packet
            name = data[13:45].decode('ascii').strip()
            self.server.responder.handle_poisoned_request('NBT-NS', self.client_address[0], name)
            
class MDNSRequestHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        if data[2:4] == b'\x00\x00':  # Query packet
            # Parse MDNS query (simplified)
            name = data[12:].split(b'\x00')[0].decode('utf-8')
            self.server.responder.handle_poisoned_request('MDNS', self.client_address[0], name)