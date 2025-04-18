from scapy.all import sniff, IP, TCP, conf
from scapy.arch import get_windows_if_list
from typing import Optional, Dict, List
import threading
import logging
import sys
import re
import platform
import ctypes
import os

class PacketSniffer:
    def __init__(self, interface: str = None):
        self.logger = logging.getLogger(__name__) # Get logger instance
        
        # Check for admin privileges
        if not self._is_admin():
            raise PermissionError("Administrator privileges required for packet capture")
            
        # Set verbosity level for Scapy
        conf.verb = 0
        
        self.interface = self._get_interface_name(interface)
        self.running = False
        self.capture_thread: Optional[threading.Thread] = None

    def _is_admin(self) -> bool:
        try:
            if platform.system() == 'Windows':
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def _get_interface_name(self, interface: str) -> str:
        """Get the correct interface name for the current platform"""
        if not interface:
            raise ValueError("Network interface name is required")
            
        try:
            if platform.system() == 'Windows':
                interfaces = get_windows_if_list()
                for iface in interfaces:
                    if interface.lower() in iface['name'].lower() or interface.lower() in iface['description'].lower():
                        self.logger.info(f"Found matching interface: {iface['name']} ({iface['description']})")
                        return iface['name']
                        
                available = "\n".join([f"- {i['name']} ({i['description']})" for i in interfaces])
                raise ValueError(f"Interface '{interface}' not found.\nAvailable interfaces:\n{available}")
            else:
                # For non-Windows systems, return the interface name as-is
                return interface
        except Exception as e:
            self.logger.error(f"Error finding interface: {e}")
            if "Npcap is not installed" in str(e):
                self.logger.error("Please install Npcap from https://npcap.com/")
            raise

    def start(self):
        """Start packet capture in a separate thread"""
        try:
            self.running = True
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            self.logger.info(f"Packet capture started on interface {self.interface}")
        except Exception as e:
            self.logger.error(f"Failed to start capture: {e}")
            raise

    def stop(self):
        """Stop the packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()
        self.logger.info("Packet capture stopped")

    def _capture_packets(self):
        """Capture packets using scapy"""
        try:
            # Disable scapy warnings
            conf.verb = 0
            sniff(
                iface=self.interface,
                filter="tcp port 445 or tcp port 139",
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            self.running = False

    def _packet_callback(self, packet):
        """Process captured packets"""
        if IP in packet and TCP in packet:
            try:
                # Look for NTLM authentication packets
                if self._is_ntlm_auth(packet):
                    ntlm_data = self._extract_ntlm_data(packet)
                    if ntlm_data:
                        self.logger.info(f"Captured NTLM hash from {packet[IP].src}")
                        return ntlm_data
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
        return None

    def _is_ntlm_auth(self, packet) -> bool:
        """Check if packet contains NTLM authentication"""
        try:
            return b'NTLMSSP' in bytes(packet[TCP].payload)
        except:
            return False

    def _extract_ntlm_data(self, packet) -> Optional[Dict]:
        """Extract NTLM authentication data from packet"""
        try:
            # Basic NTLM extraction - you might want to enhance this
            payload = bytes(packet[TCP].payload)
            if b'NTLMSSP' in payload:
                # Implement proper NTLM parsing here
                return {
                    'source': packet[IP].src,
                    'destination': packet[IP].dst,
                    'payload': payload.hex()
                }
        except Exception as e:
            self.logger.error(f"Error extracting NTLM data: {e}")
        return None

def start_capture(interface: str = None) -> PacketSniffer:
    """Start packet capture and return the sniffer instance"""
    sniffer = PacketSniffer(interface)
    sniffer.start()
    return sniffer