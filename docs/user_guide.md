# User Guide for NTLM Relay Tool

## Introduction
The NTLM Relay Tool is designed to capture NTLM authentication requests, store the captured hashes, and exploit them through relay attacks or password cracking. This guide provides instructions on how to use the tool effectively.

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ntlm-relay-tool.git
   ```
2. Navigate to the project directory:
   ```
   cd ntlm-relay-tool
   ```
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Configuration
Before running the tool, ensure that the configuration files are set up correctly:
- **Database Configuration**: Edit `config/database.ini` to set your database connection parameters.
- **Logging Configuration**: Adjust `config/logging.ini` to configure logging settings.

## Usage
### Starting the Capture
To begin capturing NTLM authentication requests, run the following command:
```
python src/main.py capture
```
This will start the Responder module, which listens for NTLM requests.

### Stopping the Capture
To stop the capture process, you can use the following command:
```
python src/main.py stop_capture
```

### Exploiting Captured Hashes
Once you have captured NTLM hashes, you can exploit them using the relay functionality:
```
python src/main.py relay
```

### Cracking Passwords
To attempt to crack the captured hashes, use the following command:
```
python src/main.py crack
```
Make sure to provide a wordlist located in the `data/wordlists` directory.

## Logging
The tool logs its activities. Check the logs for any errors or important information regarding the operations performed.

## Troubleshooting
- Ensure that all dependencies are installed.
- Check the configuration files for correct settings.
- Review the logs for any error messages.

## Conclusion
This user guide provides a basic overview of how to operate the NTLM Relay Tool. For more detailed technical information, refer to the `docs/technical.md` file.