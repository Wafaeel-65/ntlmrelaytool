# NTLM Relay Tool

NTLM Relay Tool is a framework for capturing NTLM authentication attempts on network interfaces and relaying them to target services. It supports parsing, responding, cracking, relaying NTLM authentication, and storing results in MongoDB.

## Features
- Packet capture and parsing of NTLM authentication
- NTLM authentication relaying to SMB, LDAP, HTTP endpoints
- Hash handling and optional cracking
- MongoDB storage for authentication events and results
- Extensible modules and utilities

## Requirements
- Python 3.11+
- MongoDB instance (for storage)
- libpcap-compatible packet capture (e.g., WinPcap/Npcap on Windows)

## Installation

```bash
git clone https://github.com/your_org/ntlmrelaytool.git
cd ntlmrelaytool
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Copy `config/logging.ini` and `config/mongodb.ini` to your working directory and update settings as needed.

- `logging.ini`: configure log levels and destinations
- `mongodb.ini`: set `uri`, `database`, and `collection` names

## Usage

```bash
python src/main.py --interface eth0 --target smb://10.0.0.5
```

Or use provided scripts:

- `scripts/list_interfaces.py`: List available network interfaces.
- `scripts/setup_db.py`: Initialize MongoDB collections.
- `scripts/setup_mongodb.py`: Start a local MongoDB instance (Docker).
- `scripts/cleanup.py`: Clean captured data and logs.

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