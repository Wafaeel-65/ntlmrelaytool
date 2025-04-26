# User Guide for NTLM Relay Tool

## Introduction
The NTLM Relay Tool captures NTLM authentication requests, relays them to target services, optionally cracks hashes, and stores results in MongoDB.

## Requirements and Installation
1. Clone the repository:
   ```bash
git clone https://github.com/your_org/ntlmrelaytool.git
cd ntlmrelaytool
```  
2. Create and activate a virtual environment:
   ```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```  
3. Install dependencies:
   ```bash
pip install -r requirements.txt
```

## Configuration
Copy and edit the following files in the `config/` directory:

- `logging.ini`: Configure logging levels and handlers.
- `mongodb.ini`: Set MongoDB `uri`, `database`, and collection names.

## Usage

### Listing Network Interfaces
Use the provided script to list available network interfaces:
```bash
python scripts/list_interfaces.py
```

### Responder (Poison) Mode
Start capturing and poisoning NTLM negotiations:
```bash
python src/main.py poison --interface <interface_name>
```
Press Ctrl+C to stop.

### Relay Mode
Relay captured NTLM authentication to a target service:
```bash
python src/main.py relay --interface <interface_name> --target <target_address>
```
Example target formats:
- SMB: `smb://10.0.0.5`
- HTTP: `http://example.com`

### Listing Captured Results
Display stored authentication events and hashes from MongoDB:
```bash
python src/main.py list
```

## Additional Scripts
- `scripts/setup_db.py`: Initialize MongoDB collections.
- `scripts/setup_mongodb.py`: Launch a local MongoDB instance (Docker).
- `scripts/cleanup.py`: Remove logs and temporary data.

## Logging
All tool output is logged to `ntlm_relay.log` and to console. Adjust `config/logging.ini` for verbosity and log destinations.

## Troubleshooting
- Ensure you run commands with administrator/root privileges.
- Confirm dependencies are installed and config files are correct.
- Review `ntlm_relay.log` and `app.log` for errors.

For further details, see the Technical Documentation in `docs/technical.md` and the project README.