# Technical Documentation for NTLM Relay Tool

## Overview
The NTLM Relay Tool is designed to capture NTLM authentication requests, store the captured hashes securely, and exploit them through relay attacks and password cracking. This document provides a technical overview of the project's architecture, modules, and functionalities.

## Project Structure
The project is organized into several key directories and modules:

- **src/**: Contains the main application source code.
  - **modules/**: Divided into three main sub-modules:
    - **capture/**: Handles the capture of NTLM authentication requests.
    - **storage/**: Manages the storage of captured data and database interactions.
    - **exploit/**: Contains functionalities for exploiting captured hashes.
  - **utils/**: Provides utility functions and classes, such as logging.
  - **main.py**: The entry point of the application.

- **tests/**: Contains unit tests for each module to ensure functionality and reliability.

- **scripts/**: Includes scripts for database setup and cleanup operations.

- **config/**: Holds configuration files for database and logging settings.

- **data/**: Contains wordlists used for password cracking.

- **docs/**: Documentation files, including technical documentation and user guides.

## Modules

### Capture Module
- **responder.py**: Implements the `Responder` class for capturing NTLM authentication requests.
  - **Methods**:
    - `start_capture()`: Begins listening for NTLM requests.
    - `stop_capture()`: Stops the capture process.

- **parser.py**: Provides functions for parsing captured NTLM hashes.
  - **Function**:
    - `parse_hashes(raw_data)`: Takes raw data and returns structured hash information.

### Storage Module
- **database.py**: Manages database connections and operations.
  - **Class**: `Database`
    - **Methods**:
      - `connect()`: Establishes a connection to the database.
      - `disconnect()`: Closes the database connection.
      - `execute_query(query)`: Executes a given SQL query.

- **models.py**: Defines data models for the application.
  - **Classes**:
    - `Target`: Represents a target with properties like `id`, `username`, and `hash`.
    - `Credential`: Represents credentials with similar properties.

### Exploit Module
- **relay.py**: Contains the `Relay` class for managing NTLM relay attacks.
  - **Methods**:
    - `start_relay()`: Initiates the relay attack.
    - `stop_relay()`: Stops the relay process.

- **cracker.py**: Implements the `Cracker` class for password cracking.
  - **Method**:
    - `crack_hash(hash, wordlist)`: Attempts to find the original password for a given hash using a specified wordlist.

## Utilities
- **logger.py**: Provides logging functionality.
  - **Class**: `Logger`
    - **Methods**:
      - `log_info(message)`: Logs informational messages.
      - `log_error(message)`: Logs error messages.

## Testing
The project includes unit tests for each module to ensure that all functionalities work as expected. Tests are located in the `tests/` directory and cover the capture, storage, and exploit modules.

## Configuration
Configuration files for the database and logging are located in the `config/` directory. These files allow for easy adjustments to settings without modifying the source code.

## Conclusion
The NTLM Relay Tool is a modular and extensible application designed for security professionals to analyze and exploit NTLM authentication vulnerabilities. This documentation provides a comprehensive overview of the project's structure and functionalities, facilitating further development and usage.