from typing import Tuple, Dict
from passlib.hash import nthash

def process_ntlm_hash(hash_data: Dict) -> Tuple[str, str, str]:
    """
    Process NTLM hash data and extract username, domain, and hash value.
    
    Args:
        hash_data (dict): Dictionary containing NTLM hash data
            Expected format: {
                'username': str,
                'domain': str,
                'hash': str
            }
    
    Returns:
        Tuple[str, str, str]: (username, domain, hash_value)
    """
    username = hash_data.get('username', '')
    domain = hash_data.get('domain', '')
    hash_value = hash_data.get('hash', '')
    
    # Validate hash format
    if hash_value and not _is_valid_ntlm_hash(hash_value):
        raise ValueError("Invalid NTLM hash format")
        
    return username, domain, hash_value

def verify_hash(password: str, ntlm_hash: str) -> bool:
    """
    Verify if a password matches an NTLM hash.
    
    Args:
        password (str): Clear text password to verify
        ntlm_hash (str): NTLM hash to compare against
    
    Returns:
        bool: True if password matches hash, False otherwise
    """
    if not password or not ntlm_hash:
        return False
    
    calculated_hash = calculate_ntlm_hash(password)
    return calculated_hash.lower() == ntlm_hash.lower()

def calculate_ntlm_hash(password: str) -> str:
    """
    Calculate NTLM hash from a password using passlib.
    
    Args:
        password (str): Password to hash
    
    Returns:
        str: NTLM hash of the password
    """
    return nthash.hash(password)

def _is_valid_ntlm_hash(hash_value: str) -> bool:
    """
    Validate NTLM hash format.
    
    Args:
        hash_value (str): Hash value to validate
    
    Returns:
        bool: True if valid NTLM hash format, False otherwise
    """
    if len(hash_value) != 32:
        return False
        
    try:
        int(hash_value, 16)
        return True
    except ValueError:
        return False