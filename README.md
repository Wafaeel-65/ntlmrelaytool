# NTLM Relay Tool

NTLM Relay Tool is a framework for capturing NTLM authentication attempts on network interfaces and relaying them to target services. It supports parsing, responding, cracking, relaying NTLM authentication, and storing results in MongoDB.

## Features
- Packet capture and parsing of NTLM authentication
- NTLM authentication relaying to SMB, LDAP, HTTP endpoints (often via `impacket-ntlmrelayx`)
- LLMNR/NBT-NS/MDNS poisoning to capture credentials
- Hash handling and optional cracking
- MongoDB storage for authentication events and results
- Combined attack mode to run poisoning and relaying concurrently
- Extensible modules and utilities

## Requirements
- Python 3.11+
- MongoDB instance (for storage)
- libpcap-compatible packet capture (e.g., WinPcap/Npcap on Windows)
- `impacket-ntlmrelayx` installed and in PATH for reliable relaying

## Installation

```bash
git clone https://github.com/Wafaeel-65/ntlmrelaytool.git
cd ntlmrelaytool
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
pip install -r requirements.txt
# Ensure impacket is installed (often included via requirements, but verify)
# pip install impacket
```

## Configuration

Copy `config/logging.ini` and `config/mongodb.ini` to your working directory and update settings as needed.

- `logging.ini`: configure log levels and destinations
- `mongodb.ini`: set `uri`, `database`, and `collection` names

## Usage

**List available network interfaces:**
```bash
sudo python src/main.py list --interfaces # Note: 'list --interfaces' is not a real command, use external tools or check OS
# Or use the provided script (if it exists and works on your OS):
# python scripts/list_interfaces.py
```
*(Note: Requires administrator/root privileges for raw socket access and interface listing/binding)*

**Run poisoning only:**
```bash
sudo python src/main.py poison --interface <interface_name>
```

**Run relaying only (requires target):**
```bash
sudo python src/main.py relay --interface <interface_name> --target <target_ip_or_hostname>
```

**Run combined attack (poisoning and relaying):**
```bash
sudo python src/main.py attack --interface <interface_name> --target <target_ip_or_hostname>
```

**List captured results from MongoDB:**
```bash
python src/main.py list
```

**Enable debug logging:**
Add the `--debug` flag to any command, e.g.:
```bash
sudo python src/main.py attack --interface eth0 --target 192.168.1.100 --debug
```
## Modules

Detailed technical documentation can be found in `docs/technical.md`. For quick start, see the User Guide in `docs/user_guide.md`.

## Testing

Run unit tests with pytest:

```bash
pytest
```

## Contributing

Contributions welcome! Please open issues and pull requests.

## License

MIT License. See `LICENSE` for details.