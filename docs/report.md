# NTLM Relay Tool - Comprehensive Technical Report

## 1. Executive Summary

The NTLM Relay Tool is a specialized cybersecurity framework designed to test, analyze, and demonstrate NTLM authentication vulnerabilities in Windows network environments. It implements a complete solution for capturing NTLM authentication attempts, poisoning name resolution protocols, relaying credentials to target services, and optionally cracking hashes - all while providing robust storage, logging, and analysis capabilities.

This tool is primarily intended for defensive security testing, allowing organizations to:
- Validate their defenses against NTLM relay attacks
- Identify misconfigured services susceptible to relay attacks
- Improve security awareness through controlled demonstrations
- Test network traffic monitoring and intrusion detection capabilities

The framework is built with modularity, extensibility, and ease of use in mind, allowing security professionals to quickly deploy and adapt it to various testing scenarios.

## 2. Project Overview

### 2.1 Purpose and Scope

The NTLM Relay Tool addresses the persistent security challenge posed by the NTLM authentication protocol's susceptibility to relay attacks. Despite being largely superseded by Kerberos, NTLM remains widely used in many organizations, especially in legacy systems and mixed environments. 

This tool provides:
- A comprehensive implementation of NTLM relay techniques
- Multiple modes of operation (capture, poison, relay)
- Database persistence for analysis and reporting
- Advanced configuration options for different testing scenarios
- Detailed logging and analysis capabilities

### 2.2 Key Components

The NTLM Relay Tool consists of four main components:

1. **Capture Module**: Passively monitors network traffic for NTLM authentication attempts
2. **Poisoning Module**: Actively responds to network name resolution protocols to trigger NTLM authentication
3. **Relay Module**: Forwards captured authentication attempts to target services
4. **Storage Module**: Preserves captured data, authentication attempts, and results

Utility components provide logging, configuration, hash handling, and other supporting functions.

### 2.3 Target Audience

The tool is designed for:
- Security professionals conducting authorized penetration tests
- Network administrators validating security controls
- Security trainers demonstrating NTLM vulnerabilities
- Red teams performing controlled attack simulations

## 3. Technical Architecture

### 3.1 High-Level Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Capture/      │         │     Exploit      │         │    Storage      │
│   Poison        │───────▶│     Module       │───────▶│    Module       │
│   Module        │         │                  │         │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
        ▲                           ▲                            ▲
        │                           │                            │
        └───────────────┬───────────┴────────────┬──────────────┘
                        │                        │
                        ▼                        ▼
              ┌─────────────────┐     ┌───────────────────┐
              │  Configuration  │     │     Utilities     │
              │     Module      │     │                   │
              └─────────────────┘     └───────────────────┘
```

The architecture follows a modular design with clear separation of concerns:

1. **Core Modules**: Handle specific functionalities like capturing, poisoning, relaying
2. **Utility Layer**: Provides common functions across modules
3. **Data Storage**: Manages persistence and retrieval of captured data
4. **Configuration**: Controls tool behavior and settings
5. **Main Controller**: Orchestrates and coordinates all components

### 3.2 Data Flow

1. User configures and launches the tool in a specific mode
2. Capture/Poison module collects or triggers NTLM authentication attempts
3. Authentication data is optionally relayed to target services
4. Results (successful/failed authentications) are stored in MongoDB
5. Data is available for review, analysis, and reporting

### 3.3 Technology Stack

- **Core Language**: Python 3.11+
- **Networking**: Raw sockets, Scapy, Impacket
- **Authentication**: NTLM protocol implementation
- **Storage**: MongoDB, SQLite
- **Crypto**: PyCryptodome, Passlib
- **Testing**: Pytest, coverage tools
- **Logging**: Python's logging module

## 4. Module Descriptions

### 4.1 Capture Module (src/modules/capture)

#### 4.1.1 Parser (parser.py)

The parser component extracts and processes NTLM authentication data from network packets:
- Identifies NTLM negotiate/challenge/response messages
- Extracts usernames, domains, and hashes
- Parses NTLM protocol fields and message types
- Provides structured data for storage and relay

#### 4.1.2 Responder (responder.py)

The responder component implements active poisoning techniques:
- Responds to LLMNR, NetBIOS, and mDNS queries
- Creates malicious SMB and HTTP servers to capture authentication
- Automatically adapts to different network interface configurations
- Provides platform-specific implementations for Windows and Linux

### 4.2 Exploit Module (src/modules/exploit)

#### 4.2.1 Relay (relay.py)

The relay component forwards captured authentication to target services:
- Establishes connections to target services (SMB, HTTP, LDAP)
- Forwards NTLM messages between client and target
- Maintains session state throughout authentication flow
- Records successful relay attempts and accessed resources

#### 4.2.2 NTLM Relay Server (ntlmrelayserver.py)

The NTLM relay server handles the technical details of SMB protocol:
- Implements SMB negotiation and session setup
- Processes NTLM authentication messages
- Relays credentials to targets while maintaining protocol state
- Handles connection establishment and teardown

#### 4.2.3 Cracker (cracker.py)

The cracker component attempts to recover plaintext passwords:
- Uses wordlist-based attacks against captured hashes
- Implements NTLM hash calculation and verification
- Provides performance optimizations for faster cracking
- Integrates with storage for recording cracked credentials

### 4.3 Storage Module (src/modules/storage)

#### 4.3.1 Database (database.py)

The database component abstracts database operations:
- Provides connection and query execution interface
- Implements schema creation and management
- Handles transaction control and error recovery
- Supports multiple database engines (currently SQLite)

#### 4.3.2 Models (models.py)

The models component defines data structures:
- Implements object models for targets, credentials, plugins
- Provides data validation and typing
- Defines relationships between different data entities
- Supports serialization and deserialization

### 4.4 Utilities (src/utils)

#### 4.4.1 Config (config.py)

The configuration utility loads and manages settings:
- Reads configuration from INI files
- Provides typed access to configuration values
- Handles default values and configuration validation
- Centralizes configuration management

#### 4.4.2 Hash Handler (hash_handler.py)

The hash handler utility processes NTLM hashes:
- Validates NTLM hash format
- Calculates NTLM hashes from passwords
- Verifies passwords against hashes
- Extracts authentication data from NTLM messages

#### 4.4.3 MongoDB Handler (mongo_handler.py)

The MongoDB handler manages the MongoDB connection:
- Establishes and maintains database connection
- Implements retry logic for connection failures
- Provides CRUD operations for authentication data
- Handles connection pooling and resource management

#### 4.4.4 Packet Sniffer (packet_sniffer.py)

The packet sniffer utility captures network traffic:
- Uses Scapy for packet capture and analysis
- Filters traffic for NTLM-related protocols
- Extracts authentication data from packets
- Handles platform-specific capture requirements

#### 4.4.5 Logger (logger.py)

The logger utility provides centralized logging:
- Configures logging based on configuration
- Supports multiple log destinations
- Implements log rotation and management
- Provides consistent logging interface

### 4.5 Main Controller (src/main.py)

The main controller orchestrates all components:
- Parses command-line arguments
- Initializes components based on user configuration
- Manages component lifecycle
- Coordinates data flow between components
- Handles error conditions and cleanup

## 5. Usage Scenarios

### 5.1 Passive Capture

In passive capture mode, the tool monitors network traffic for NTLM authentication:
1. User runs the tool with packet capture parameters
2. Tool captures and analyzes network traffic
3. NTLM authentication attempts are extracted and stored
4. User reviews captured authentication data

**Example command:**
```bash
python src/main.py --interface eth0
```

### 5.2 Active Poisoning

In active poisoning mode, the tool responds to network queries:
1. User runs the tool with poisoning parameters
2. Tool responds to LLMNR/NetBIOS/mDNS queries
3. Clients attempt to authenticate to the tool
4. Authentication attempts are captured and stored

**Example command:**
```bash
python src/main.py poison --interface eth0
```

### 5.3 Relay Attack

In relay mode, the tool forwards authentication to target services:
1. User runs the tool with relay parameters
2. Tool captures authentication attempts
3. Authentication is relayed to specified target
4. Successful relays are recorded and reported

**Example command:**
```bash
python src/main.py relay --interface eth0 --target 192.168.1.10
```

### 5.4 Result Analysis

The tool provides result analysis and reporting:
1. User runs the tool with list parameters
2. Tool queries storage for captured authentication
3. Results are displayed in structured format
4. User analyzes authentication patterns and success rates

**Example command:**
```bash
python src/main.py list
```

## 6. Implementation Details

### 6.1 Code Organization

The project follows a clean, modular structure:
- **src/**: Contains all source code
  - **modules/**: Functional modules (capture, exploit, storage)
  - **utils/**: Utility functions and helpers
- **config/**: Configuration files
- **docs/**: Documentation
- **scripts/**: Utility scripts
- **tests/**: Test suite

### 6.2 Error Handling

The tool implements comprehensive error handling:
- Graceful degradation when components fail
- Detailed error logging
- User-friendly error messages
- Recovery mechanisms where possible

### 6.3 Testing Strategy

The project includes a test suite:
- Unit tests for individual components
- Integration tests for component interactions
- Functional tests for end-to-end workflows
- Test data and fixtures

### 6.4 Security Considerations

The tool includes security measures to prevent misuse:
- Requires administrator/root privileges
- Checks for authorization before execution
- Includes documentation about ethical usage
- Implements logging of all activities

## 7. Deployment and Requirements

### 7.1 System Requirements

- Python 3.11+
- Administrator/root privileges
- Network interface with promiscuous mode support
- MongoDB instance (for storage)
- Additional Python packages (see requirements.txt)

### 7.2 Installation Process

1. Clone the repository
2. Create a virtual environment
3. Install dependencies
4. Configure MongoDB connection
5. Adjust settings in configuration files
6. Run the tool with appropriate parameters

### 7.3 Dependencies

Key dependencies include:
- Impacket for NTLM protocol implementation
- Scapy for packet capture and analysis
- PyMongo for MongoDB interaction
- PyCryptodome for cryptographic operations
- Passlib for hash processing

## 8. Future Enhancements

### 8.1 Potential Improvements

1. **Additional Protocol Support**: Expand beyond SMB to include HTTP, LDAP, MSSQL relay
2. **Enhanced Reporting**: Generate PDF/HTML reports of capture and relay results
3. **Web Interface**: Add a web-based dashboard for configuration and monitoring
4. **Integration Capabilities**: Add API endpoints for integration with other security tools
5. **Automated Exploitation**: Implement post-relay exploitation modules

### 8.2 Known Limitations

1. Platform-specific behaviors (especially network capture)
2. Potential for detection by security controls
3. Limited support for some authentication edge cases
4. Performance concerns with large-scale captures

## 9. Ethical and Legal Considerations

### 9.1 Intended Use

The NTLM Relay Tool is intended for:
- Authorized security testing
- Security education and training
- Defensive security validation
- Security research in controlled environments

### 9.2 Legal Warning

Use of this tool without proper authorization may violate:
- Computer fraud and abuse laws
- Network access policies
- Privacy regulations
- Corporate security policies

Always obtain explicit written permission before using this tool in any environment.

## 10. Conclusion

The NTLM Relay Tool provides a comprehensive solution for testing and validating NTLM authentication security. Its modular design, extensive configuration options, and detailed logging make it a valuable tool for security professionals. By following proper usage guidelines and legal considerations, organizations can use this tool to improve their security posture against NTLM relay attacks.

---

## Appendix A: Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `list-interface` | List available network interfaces | `python src/main.py list-interface` |
| `poison` | Start poisoning mode | `python src/main.py poison --interface eth0` |
| `relay` | Start relay mode | `python src/main.py relay --interface eth0 --target 192.168.1.10` |
| `list` | List captured results | `python src/main.py list` |

## Appendix B: Configuration Reference

| File | Purpose | Example Setting |
|------|---------|-----------------|
| `logging.ini` | Configure logging | `level=DEBUG` |
| `mongodb.ini` | Configure MongoDB | `host=localhost` |

## Appendix C: Class Diagram

```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│ ResponderCapture│     │     Relay      │     │  MongoDBHandler│
├────────────────┤     ├────────────────┤     ├────────────────┤
│ start_poisoning()│     │ start_relay()  │     │ store_capture()│
│ stop_poisoning() │     │ stop_relay()   │     │ get_captures() │
└────────────────┘     └────────────────┘     └────────────────┘
        ▲                      ▲                      ▲
        │                      │                      │
        │                      │                      │
        │                      ▼                      │
┌────────────────┐     ┌────────────────┐            │
│  PacketSniffer  │     │NTLMRelayServer │            │
├────────────────┤     ├────────────────┤            │
│ start()         │     │ start()        │            │
│ stop()          │     │ stop()         │            │
└────────────────┘     └────────────────┘            │
        │                      │                      │
        │                      │                      │
        ▼                      ▼                      ▼
┌────────────────────────────────────────────────────────────┐
│                           Main                              │
├────────────────────────────────────────────────────────────┤
│ setup_logging()                                             │
│ list_interfaces()                                           │
│ list_results()                                              │
└────────────────────────────────────────────────────────────┘
```

## Appendix D: Use Case Diagram

```
┌────────────────────────────────────────────────────────────┐
│                   NTLM Relay Tool                           │
│                                                            │
│  ┌───────────┐    ┌───────────┐     ┌───────────┐         │
│  │  View     │    │  Poison   │     │  Relay    │         │
│  │ Interfaces│    │  Network  │     │  Auth     │         │
│  └───────────┘    └───────────┘     └───────────┘         │
│        ▲                ▲                 ▲               │
│        │                │                 │               │
│        │                │                 │               │
└────────┼────────────────┼─────────────────┼───────────────┘
         │                │                 │
         │                │                 │
         ▼                ▼                 ▼
     ┌───────────────────────────────────────────┐
     │             Security Analyst              │
     └───────────────────────────────────────────┘
```

Report generated on April 29, 2025