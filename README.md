# ntlm-relay-tool/README.md

# NTLM Relay Tool

## Overview

The NTLM Relay Tool is a modular application designed to capture NTLM hashes, store them securely, and exploit them through NTLM relay attacks and password cracking. This tool is intended for security professionals and researchers to analyze NTLM authentication vulnerabilities.

## Features

- **Capture Module**: Captures NTLM authentication requests using the Responder tool.
- **Storage Module**: Manages the storage of captured hashes and related data in a database.
- **Exploit Module**: Facilitates NTLM relay attacks and password cracking using captured hashes.


## Testing

To run the unit tests, use:
```
pytest tests/
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.