# NTLM Relay Tool Technical Documentation

## Architecture Overview

The NTLM Relay Tool is organized into modular components:

1. **Capture Layer**  
   - Listens on network interfaces and captures NTLM authentication traffic.  
   - Parses raw packets to extract NTLM messages.
2. **Responder Layer**  
   - Crafts and sends NTLM challenge/response packets to clients.  
   - Handles negotiation and authentication flows.
3. **Exploit Layer**  
   - Relays valid NTLM credentials to target services (SMB, LDAP, HTTP).  
   - Optional cracking of captured hashes.
4. **Storage Layer**  
   - Persists events, credentials, and results into MongoDB.  
   - Provides data models and database access abstraction.
5. **Utility Layer**  
   - Shared configuration, logging, hash processing, MongoDB connection, and packet sniffing.

## Module Details

### capture

#### parser.py  
- Implements packet parsing logic using scapy.  
- Extracts NTLM messages (Type 1, 2, 3) from network traffic.

#### responder.py  
- Generates NTLM challenge messages.  
- Responds to clients to progress through authentication flows.

### exploit

#### ntlmrelayserver.py  
- Orchestrates relay attacks by accepting client auth and forwarding to targets.

#### relay.py  
- Handles protocol-specific relaying logic (SMB, LDAP, HTTP).  
- Manages connection pooling and timeouts.

#### cracker.py  
- Optional hash cracking using external tools (e.g., hashcat).  
- Configurable wordlists and rules.

### storage

#### database.py  
- Initializes MongoDB client and database/collection configurations.  
- Provides CRUD operations for events and credentials.

#### models.py  
- Defines data models for authentication events and hash results.  
- Uses Pydantic or similar for schema validation.

### utils

#### config.py  
- Loads `logging.ini` and `mongodb.ini`.  
- Exposes application settings via typed objects.

#### logger.py  
- Configures Python logging based on `logging.ini`.  
- Supports console and file handlers.

#### hash_handler.py  
- Processes NTLM hashes for storage and optional cracking.  
- Handles formatting and salt extraction.

#### mongo_handler.py  
- Provides helper functions for MongoDB operations.  
- Wraps exceptions and retry logic.

#### packet_sniffer.py  
- Abstracts pcap interface for capturing live traffic.  
- Supports reading from pcap files for offline analysis.

## Configuration Files

- `config/logging.ini`: Logging levels and handlers.  
- `config/mongodb.ini`: MongoDB `uri`, `database`, `collections`.

## Extensibility

- Add new relaying protocols by extending `exploit.relay`.  
- Customize parsing or responder logic in the `capture` module.  
- Plug in alternative storage backends by implementing storage interfaces.