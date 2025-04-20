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

# Add the project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src.utils.db_handler import DatabaseHandler
from src.utils.hash_handler import process_ntlm_hash
from src.utils.packet_sniffer import start_capture
from src.modules.exploit.relay import Relay
from src.utils.mongo_handler import MongoDBHandler

def is_admin():
    try:
        # Windows check
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin()
        # Linux/Unix check
        else:
            return os.geteuid() == 0
    except AttributeError: # Handle cases where geteuid might not be available (shouldn't happen on Linux)
        return False
    except Exception: # Catch other potential errors like ctypes issues on non-Windows
        return False

def list_interfaces():
    """List available network interfaces"""
    conf.verb = 0  # Disable Scapy verbosity
    interfaces = get_if_list()
    print("\nAvailable Network Interfaces:")
    print("=" * 60)
    for iface in interfaces:
        print(f"- {iface}")
    print("\nUsage example:")
    print('python src/main.py capture --interface "<interface_name>"')

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ntlm_relay.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def list_results(mongo_handler, sql_handler, logger):
    """List captured results from both databases"""
    try:
        # Try MongoDB first
        if mongo_handler:
            mongo_captures = mongo_handler.get_captures()
            if mongo_captures:
                print("\nMongoDB Captures:")
                print("=" * 80)
                print(f"{'ID':<24} {'Timestamp':<25} {'Source IP':<15} {'Username':<15} {'Domain'}")
                print("-" * 80)
                for capture in mongo_captures:
                    timestamp = capture.get('timestamp', '').strftime('%Y-%m-%d %H:%M:%S')
                    print(f"{str(capture['_id']):<24} {timestamp:<25} {capture.get('source', ''):<15} {capture.get('username', ''):<15} {capture.get('domain', '')}")
                print("=" * 80)
        
        # Get SQLite results
        results = sql_handler.execute_query(
            """SELECT r.ID_RESULTAT, r.ID_PLUGIN, r.DATE_RESULTAT, r.STATUT, r.DETAILS, p.NTLM_KEY 
               FROM RESULTAT r 
               JOIN PLUGIN p ON r.ID_PLUGIN = p.ID_PLUGIN 
               ORDER BY r.DATE_RESULTAT DESC"""
        )
        
        if results:
            print("\nSQLite Captures:")
            print("=" * 80)
            print(f"{'ID':<5} {'PluginID':<10} {'Timestamp':<25} {'Status':<10} {'Details'}")
            print("-" * 80)
            for row in results:
                timestamp = row[2].strftime('%Y-%m-%d %H:%M:%S') if row[2] else ''
                print(f"{row[0]:<5} {row[1]:<10} {timestamp:<25} {row[3]:<10} {row[4]}")
            print("=" * 80)
            
        if not mongo_captures and not results:
            logger.info("No captures found in either database.")
            
    except Exception as e:
        logger.error(f"Failed to retrieve results: {e}")

def main():
    logger = setup_logging()
    
    parser = argparse.ArgumentParser(description='NTLM Relay Tool')
    parser.add_argument('command', choices=['capture', 'stop_capture', 'relay', 'crack', 'list-interfaces', 'list-results'],
                       help='Command to execute')
    parser.add_argument('--interface', help='Network interface to capture/relay on')
    parser.add_argument('--port', type=int, default=445, help='Port to listen on (default: 445)')
    parser.add_argument('--target', help='Target host for relay attack')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

    # Check for admin privileges for commands that need them
    if args.command in ['capture', 'relay'] and not is_admin():
        logger.error("This command requires administrator privileges. Please run as administrator.")
        return

    # Special handling for list-interfaces command
    if args.command == 'list-interfaces':
        list_interfaces()
        return
        
    # Initialize databases
    db = DatabaseHandler()
    try:
        db.initialize_database()
        logger.info("SQLite database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize SQLite database: {e}")
        return

    # Initialize MongoDB if available
    mongo_db = None
    try:
        mongo_db = MongoDBHandler()
        logger.info("MongoDB connection established")
    except Exception as e:
        logger.warning(f"MongoDB not available: {e}")
    
    try:
        if args.command == 'list-results':
            list_results(mongo_db, db, logger)
            return
            
        if args.command == 'capture':
            if not args.interface:
                logger.error("Interface is required for capture mode")
                list_interfaces()
                return
                
            logger.info(f"Starting capture mode on interface {args.interface}...")
            try:
                sniffer = start_capture(interface=args.interface)
                logger.info("Press Ctrl+C to stop capture")
                
                while True:
                    import time
                    time.sleep(1)  # Reduce CPU usage while waiting
                    
            except KeyboardInterrupt:
                logger.info("Stopping capture...")
                # Removed sniffer.stop() call - rely on daemon thread exit
            except Exception as e:
                logger.error(f"Failed to start capture: {str(e)}")
                
        elif args.command == 'stop_capture':
            logger.info("Stopping any running captures...")
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'python' in proc.info['name'].lower() and 'packet_sniffer' in ' '.join(proc.info['cmdline']):
                        proc.terminate()
                        logger.info(f"Terminated capture process {proc.info['pid']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        elif args.command == 'relay':
            if not args.target:
                logger.error("Target is required for relay mode. Use --target to specify the target host.")
                return
                
            logger.info("Starting relay attack...")
            relay = Relay(interface=args.interface or '0.0.0.0', port=args.port)
            try:
                relay.start_relay(target=args.target)
                logger.info(f"Relay server started. Listening on port {args.port}. Target: {args.target}")
                logger.info("Press Ctrl+C to stop.")
                while True:
                    import time
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Stopping relay...")
                relay.stop_relay()
                
        elif args.command == 'crack':
            logger.info("Starting password cracking...")
            # Add password cracking implementation here
            logger.info("Password cracking not implemented yet")

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        db.disconnect()
        if mongo_db:
            mongo_db.disconnect()
        logger.info("Tool execution completed")

if __name__ == "__main__":
    main()