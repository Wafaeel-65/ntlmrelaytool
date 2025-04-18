def parse_hashes(raw_data):
    """
    Parses the raw data to extract structured NTLM hash information.

    Args:
        raw_data (str): The raw data containing NTLM hashes.

    Returns:
        list: A list of dictionaries containing structured hash information.
    """
    hashes = []
    # Split the raw data into lines
    lines = raw_data.strip().split('\n')
    
    for line in lines:
        # Assuming each line contains a hash in the format: <username>:<hash>
        parts = line.split(':')
        if len(parts) == 2:
            username, hash_value = parts
            hashes.append({
                'username': username.strip(),
                'hash': hash_value.strip()
            })
    
    return hashes