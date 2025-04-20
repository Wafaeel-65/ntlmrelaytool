from pymongo import MongoClient, ASCENDING
import sys
import os
import logging
from configparser import ConfigParser

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

def setup_mongodb():
    """Setup MongoDB database and collections with proper indexes"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    try:
        # Load config
        config_path = os.path.join(project_root, 'config', 'mongodb.ini')
        if not os.path.exists(config_path):
            logger.error(f"Configuration file not found: {config_path}")
            return False
            
        config = ConfigParser()
        config.read(config_path)
        
        # Connect to MongoDB
        client = MongoClient(f"mongodb://{config['mongodb']['host']}:{config['mongodb']['port']}")
        db = client[config['mongodb']['database']]
        
        # Create collections
        captures = db.captures
        plugins = db.plugins
        results = db.results
        
        # Create indexes
        captures.create_index([("timestamp", ASCENDING)])
        captures.create_index([("source", ASCENDING)])
        captures.create_index([("username", ASCENDING)])
        captures.create_index([("domain", ASCENDING)])
        
        plugins.create_index([("created_at", ASCENDING)])
        plugins.create_index([("nom_plugin", ASCENDING)])
        
        results.create_index([("timestamp", ASCENDING)])
        results.create_index([("plugin_id", ASCENDING)])
        
        logger.info("MongoDB setup completed successfully")
        logger.info(f"Database: {config['mongodb']['database']}")
        logger.info(f"Collections created: captures, plugins, results")
        logger.info("Indexes created for better query performance")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup MongoDB: {e}")
        return False
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    success = setup_mongodb()
    sys.exit(0 if success else 1)