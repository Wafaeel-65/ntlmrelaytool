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

from src.utils.db_handler import DatabaseHandler
from src.utils.hash_handler import process_ntlm_hash
from src.utils.packet_sniffer import start_capture
from src.modules.exploit.relay import Relay
from src.utils.mongo_handler import MongoDBHandler
from src.modules.capture.responder import ResponderCapture

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
    print("\nAvailable Network Interfaces:")
    print("=" * 60)
    
    try:
        if os.name == 'nt':  # Windows
            cmd = 'powershell -Command "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status | Format-Table"'
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout)
            else:
                # Fallback to scapy if PowerShell command fails
                interfaces = get_if_list()
                for iface in interfaces:
                    print(f"- {iface}")
        else:
            # Use scapy for non-Windows systems
            interfaces = get_if_list()
            for iface in interfaces:
                print(f"- {iface}")
                
    except Exception as e:
        print(f"Error listing interfaces: {e}")
        interfaces = get_if_list()
        for iface in interfaces:
            print(f"- {iface}")
    
    print("\nUsage example:")
    print('python src/main.py capture --interface "Wi-Fi"')
    print('python src/main.py capture --interface "Ethernet"')

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
        # --- MongoDB Captures ---
        logger.info("Querying MongoDB for captures...")
        if mongo_handler:
            try:
                # Test MongoDB connection first
                try:
                    mongo_handler.db.command('ping')
                    logger.debug("MongoDB connection test successful")
                except Exception as ping_e:
                    logger.error(f"MongoDB connection test failed: {ping_e}")
                    raise

                # Check if captures collection exists
                collections = mongo_handler.db.list_collection_names()
                logger.debug(f"Found MongoDB collections: {collections}")
                if 'captures' not in collections:
                    logger.warning("No 'captures' collection found in MongoDB")
                    mongo_captures = []
                else:
                    # Get all captures from MongoDB with explicit cursor to list conversion
                    cursor = mongo_handler.captures.find({})
                    mongo_captures = list(cursor)
                    logger.debug(f"MongoDB query returned {len(mongo_captures)} captures")
                    
                    # Log first capture for debugging if available
                    if mongo_captures:
                        logger.debug(f"First capture sample: {mongo_captures[0]}")
                
                if mongo_captures:
                    print("\nMongoDB Captures:")
                    print("=" * 80)
                    print(f"{'ID':<24} {'Timestamp':<25} {'Source IP':<15} {'Username':<15} {'Domain'}")
                    print("-" * 80)
                    for capture in mongo_captures:
                        # Get values with fallbacks
                        id_str = str(capture.get('_id', 'N/A'))
                        timestamp_val = capture.get('timestamp', 'N/A')
                        if isinstance(timestamp_val, datetime):
                            timestamp_str = timestamp_val.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            timestamp_str = str(timestamp_val)
                        source = capture.get('source', 'N/A')
                        username = capture.get('username', 'N/A')
                        domain = capture.get('domain', 'N/A')
                        
                        print(f"{id_str:<24} {timestamp_str:<25} {source:<15} {username:<15} {domain}")
                    print("=" * 80)
                else:
                    logger.info("No captures found in MongoDB")
            except Exception as mongo_e:
                logger.error(f"Error querying MongoDB: {mongo_e}", exc_info=True)
        else:
            logger.warning("MongoDB handler not available")

        # --- SQLite Results ---
        logger.info("Querying SQLite for results...")
        try:
            sql_results = sql_handler.execute_query(
                """SELECT r.ID_RESULTAT, r.DATE_RESULTAT, r.STATUT, r.DETAILS, p.NOM_PLUGIN, p.NTLM_KEY
                   FROM RESULTAT r
                   LEFT JOIN PLUGIN p ON r.ID_PLUGIN = p.ID_PLUGIN
                   ORDER BY r.DATE_RESULTAT DESC"""
            )
            
            if sql_results:
                print("\nSQLite Results:")
                print("=" * 80)
                print(f"{'ID':<5} {'Timestamp':<25} {'Type':<15} {'Status':<10} {'Details/Hash'}")
                print("-" * 80)
                for row in sql_results:
                    res_id, date_res, status, details, plugin_name, ntlm_key = row
                    timestamp = date_res.strftime('%Y-%m-%d %H:%M:%S') if isinstance(date_res, datetime) else str(date_res)
                    entry_type = "Capture" if plugin_name == "NTLM Capture" else "Result"
                    
                    # For captures, show the NTLM hash, otherwise show details
                    display_value = ntlm_key if entry_type == "Capture" else details
                    print(f"{res_id:<5} {timestamp:<25} {entry_type:<15} {status or 'N/A':<10} {display_value or 'N/A'}")
                print("=" * 80)
            else:
                logger.info("No results found in SQLite database")
                
        except Exception as sql_e:
            logger.error(f"Error querying SQLite: {sql_e}", exc_info=True)

    except Exception as e:
        logger.error(f"Error in list_results: {e}", exc_info=True)

def main():
    logger = setup_logging()
    
    parser = argparse.ArgumentParser(description='NTLM Relay Tool')
    parser.add_argument('command', choices=['capture', 'stop_capture', 'relay', 'crack', 'list-interfaces', 'list-results', 'poison'],
                       help='Command to execute')
    parser.add_argument('--interface', help='Network interface to capture/relay on')
    parser.add_argument('--port', type=int, default=8445, help='Port to listen on (default: 8445)')
    parser.add_argument('--target', help='Target host for relay attack')
    parser.add_argument('--poison-type', choices=['all', 'llmnr', 'nbtns', 'mdns'], default='all',
                       help='Type of poisoning to perform (default: all)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

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
                logger.error("Permission denied. Try running without administrator privileges since we're using non-privileged ports.")
                return
            except KeyboardInterrupt:
                logger.info("Stopping poisoning servers...")
                responder.stop_poisoning()
            except Exception as e:
                logger.error(f"Failed to start poisoning: {str(e)}")
                responder.stop_poisoning()

        # --- MongoDB Captures ---
        logger.info("Querying MongoDB for captures...")
        if mongo_db:
            try:
                # Test MongoDB connection first
                try:
                    mongo_db.db.command('ping')
                    logger.debug("MongoDB connection test successful")
                except Exception as ping_e:
                    logger.error(f"MongoDB connection test failed: {ping_e}")
                    raise

                # Check if captures collection exists
                collections = mongo_db.db.list_collection_names()
                logger.debug(f"Found MongoDB collections: {collections}")
                if 'captures' not in collections:
                    logger.warning("No 'captures' collection found in MongoDB")
                    mongo_captures = []
                else:
                    # Get all captures from MongoDB with explicit cursor to list conversion
                    cursor = mongo_db.captures.find({})
                    mongo_captures = list(cursor)
                    logger.debug(f"MongoDB query returned {len(mongo_captures)} captures")
                    
                    # Log first capture for debugging if available
                    if mongo_captures:
                        logger.debug(f"First capture sample: {mongo_captures[0]}")
                
                if mongo_captures:
                    print("\nMongoDB Captures:")
                    print("=" * 80)
                    print(f"{'ID':<24} {'Timestamp':<25} {'Source IP':<15} {'Username':<15} {'Domain'}")
                    print("-" * 80)
                    for capture in mongo_captures:
                        # Get values with fallbacks
                        id_str = str(capture.get('_id', 'N/A'))
                        timestamp_val = capture.get('timestamp', 'N/A')
                        if isinstance(timestamp_val, datetime):
                            timestamp_str = timestamp_val.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            timestamp_str = str(timestamp_val)
                        source = capture.get('source', 'N/A')
                        username = capture.get('username', 'N/A')
                        domain = capture.get('domain', 'N/A')
                        
                        print(f"{id_str:<24} {timestamp_str:<25} {source:<15} {username:<15} {domain}")
                    print("=" * 80)
                else:
                    logger.info("No captures found in MongoDB")
            except Exception as mongo_e:
                logger.error(f"Error querying MongoDB: {mongo_e}", exc_info=True)
        else:
            logger.warning("MongoDB handler not available")

        # --- SQLite Results ---
        logger.info("Querying SQLite for results...")
        try:
            sql_results = db.execute_query(
                """SELECT r.ID_RESULTAT, r.DATE_RESULTAT, r.STATUT, r.DETAILS, p.NOM_PLUGIN, p.NTLM_KEY
                   FROM RESULTAT r
                   LEFT JOIN PLUGIN p ON r.ID_PLUGIN = p.ID_PLUGIN
                   ORDER BY r.DATE_RESULTAT DESC"""
            )
            
            if sql_results:
                print("\nSQLite Results:")
                print("=" * 80)
                print(f"{'ID':<5} {'Timestamp':<25} {'Type':<15} {'Status':<10} {'Details/Hash'}")
                print("-" * 80)
                for row in sql_results:
                    res_id, date_res, status, details, plugin_name, ntlm_key = row
                    timestamp = date_res.strftime('%Y-%m-%d %H:%M:%S') if isinstance(date_res, datetime) else str(date_res)
                    entry_type = "Capture" if plugin_name == "NTLM Capture" else "Result"
                    
                    # For captures, show the NTLM hash, otherwise show details
                    display_value = ntlm_key if entry_type == "Capture" else details
                    print(f"{res_id:<5} {timestamp:<25} {entry_type:<15} {status or 'N/A':<10} {display_value or 'N/A'}")
                print("=" * 80)
            else:
                logger.info("No results found in SQLite database")
                
        except Exception as sql_e:
            logger.error(f"Error querying SQLite: {sql_e}", exc_info=True)

    except Exception as e:
        logger.error(f"Error in list_results: {e}", exc_info=True)

if __name__ == "__main__":
    main()