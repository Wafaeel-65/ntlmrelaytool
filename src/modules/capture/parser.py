import re
from typing import Dict, List, Optional
import binascii

def extract_ntlm_info(payload: str) -> Optional[Dict]:
    """
    Extract NTLM information from a captured payload.
    
    Args:
        payload (str): Hex string of captured payload
        
    Returns:
        Optional[Dict]: Dictionary containing parsed NTLM information or None
    """
    try:
        # Convert hex string to bytes
        payload_bytes = binascii.unhexlify(payload)
        
        # Check for NTLMSSP signature
        if b'NTLMSSP' not in payload_bytes:
            return None
            
        # Determine NTLM message type
        if b'NTLMSSP\x00\x01\x00\x00\x00' in payload_bytes:
            msg_type = 1  # Negotiate
        elif b'NTLMSSP\x00\x02\x00\x00\x00' in payload_bytes:
            msg_type = 2  # Challenge
        elif b'NTLMSSP\x00\x03\x00\x00\x00' in payload_bytes:
            msg_type = 3  # Authenticate
        else:
            return None
            
        # Extract domain and username from Type 3 message
        if msg_type == 3:
            # Find username in payload (Unicode encoded)
            username_match = re.search(b'(?<=\x00\x00)\x00([^\x00]+?\x00){2,}', payload_bytes)
            if username_match:
                username = username_match.group(0).decode('utf-16-le').strip('\x00')
            else:
                username = None
                
            # Find domain in payload
            domain_match = re.search(b'DSI(?:\x00.|.[^\x00])*(?:\x00\x00|\xff\xff)', payload_bytes)
            if domain_match:
                domain = domain_match.group(0).decode('utf-16-le', errors='ignore').strip('\x00')
            else:
                domain = None
                
            return {
                'type': msg_type,
                'username': username,
                'domain': domain,
                'payload': payload,
                'complete_hash': True
            }
            
        return {
            'type': msg_type,
            'payload': payload,
            'complete_hash': False
        }
        
    except Exception as e:
        print(f"Error parsing NTLM payload: {e}")
        return None

def parse_hashes(raw_data: str) -> List[Dict]:
    """
    Parse captured NTLM data and extract structured hash information.
    
    Args:
        raw_data (str): Raw captured data
        
    Returns:
        List[Dict]: List of dictionaries containing structured hash information
    """
    hashes = []
    
    # Handle both string and dict input
    if isinstance(raw_data, dict):
        ntlm_info = extract_ntlm_info(raw_data.get('payload', ''))
        if ntlm_info:
            ntlm_info.update({
                'source': raw_data.get('source'),
                'destination': raw_data.get('destination')
            })
            hashes.append(ntlm_info)
    else:
        # Split the raw data into lines
        lines = raw_data.strip().split('\n')
        for line in lines:
            if 'payload' in line.lower():
                try:
                    # Extract payload from log line
                    payload = re.search(r"'payload': '([^']+)'", line)
                    if payload:
                        ntlm_info = extract_ntlm_info(payload.group(1))
                        if ntlm_info:
                            # Extract source/destination from log line
                            source = re.search(r"'source': '([^']+)'", line)
                            dest = re.search(r"'destination': '([^']+)'", line)
                            if source and dest:
                                ntlm_info.update({
                                    'source': source.group(1),
                                    'destination': dest.group(1)
                                })
                            hashes.append(ntlm_info)
                except Exception as e:
                    print(f"Error parsing line: {e}")
                    continue
    
    return hashes