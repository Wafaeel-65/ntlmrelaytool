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

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
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

def main():
    logger = setup_logging()
    
    parser = argparse.ArgumentParser(description='NTLM Relay Tool')
    parser.add_argument('command', choices=['capture', 'stop_capture', 'relay', 'crack', 'list-interfaces', 'list-results'],
                       help='Command to execute')
    parser.add_argument('--interface', help='Network interface to capture on')
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
        
    # Initialize database connection
    db = DatabaseHandler()
    try:
        db.initialize_database()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return
    
    try:
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
            logger.info("Starting relay attack...")
            relay = Relay()
            try:
                relay.start_relay()
                logger.info("Relay server started. Press Ctrl+C to stop.")
                while True:
                    pass
            except KeyboardInterrupt:
                logger.info("Stopping relay...")
                relay.stop_relay()
                
        elif args.command == 'crack':
            logger.info("Starting password cracking...")
            # Add password cracking implementation here
            logger.info("Password cracking not implemented yet")

        elif args.command == 'list-results':
            logger.info("Listing captured results from database...")
            try:
                results = db.execute_query("SELECT ID_RESULTAT, ID_PLUGIN, DATE_RESULTAT, STATUT, DETAILS FROM RESULTAT ORDER BY DATE_RESULTAT DESC")
                
                if results:
                    print("\nCaptured Results:")
                    print("=" * 60)
                    print(f"{'ID':<5} {'PluginID':<10} {'Timestamp':<25} {'Status':<10} {'Details'}")
                    print("-" * 60)
                    for row in results:
                        timestamp = datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S.%f').strftime('%Y-%m-%d %H:%M:%S') if isinstance(row[2], str) else row[2]
                        print(f"{row[0]:<5} {row[1]:<10} {str(timestamp):<25} {row[3]:<10} {row[4]}")
                    print("=" * 60)
                else:
                    logger.info("No results found in the database.")
                    
            except Exception as e:
                logger.error(f"Failed to retrieve results from database: {e}")
    
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        db.disconnect()
        logger.info("Tool execution completed")

if __name__ == "__main__":
    main()