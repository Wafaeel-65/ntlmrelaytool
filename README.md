# ntlm-relay-tool/README.md

# NTLM Relay Tool

## Overview

The NTLM Relay Tool is a modular application designed to capture NTLM hashes, store them securely, and exploit them through NTLM relay attacks and password cracking. This tool is intended for security professionals and researchers to analyze NTLM authentication vulnerabilities.

## Features

- **Capture Module**: Captures NTLM authentication requests using the Responder tool.
- **Storage Module**: Manages the storage of captured hashes and related data in a database.
- **Exploit Module**: Facilitates NTLM relay attacks and password cracking using captured hashes.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Wafaeel-65/ntlm-relay-tool.git
   cd ntlm-relay-tool
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure the database settings in `config/database.ini`.

## Usage

To run the application, execute the following command:
```
python src/main.py
```

Refer to the `docs/user_guide.md` for detailed instructions on using the tool.

## Testing

To run the unit tests, use:
```
pytest tests/
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.