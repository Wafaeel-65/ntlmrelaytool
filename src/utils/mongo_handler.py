import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any
from configparser import ConfigParser
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

class MongoDBHandler:
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.db = None
        self.captures = None
        self.plugins = None
        self.results = None
        
        if not config_path:
            config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                     'config', 'mongodb.ini')
        self.config = self._load_config(config_path)
        self.connect()

    def _load_config(self, config_path: str) -> dict:
        """Load MongoDB configuration from .ini file"""
        parser = ConfigParser()
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
        parser.read(config_path)
        if not parser.has_section('mongodb'):
            raise ValueError("MongoDB configuration section not found")
            
        return {
            'host': parser.get('mongodb', 'host'),
            'port': parser.getint('mongodb', 'port'),
            'database': parser.get('mongodb', 'database'),
            'username': parser.get('mongodb', 'username'),
            'password': parser.get('mongodb', 'password'),
            'auth_source': parser.get('mongodb', 'auth_source'),
            'data_dir': parser.get('mongodb', 'data_dir', fallback='data/mongodb'),
            'embedded_mode': parser.getboolean('mongodb', 'embedded_mode', fallback=True)
        }

    def connect(self) -> bool:
        """Establish connection to database"""
        try:
            if self.config['embedded_mode']:
                # Use TinyDB in embedded mode
                data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                      self.config['data_dir'])
                os.makedirs(data_dir, exist_ok=True)
                
                self.db = {
                    'captures': TinyDB(os.path.join(data_dir, 'captures.json'), 
                                     storage=CachingMiddleware(JSONStorage)),
                    'plugins': TinyDB(os.path.join(data_dir, 'plugins.json'),
                                    storage=CachingMiddleware(JSONStorage)),
                    'results': TinyDB(os.path.join(data_dir, 'results.json'),
                                    storage=CachingMiddleware(JSONStorage))
                }
                self.captures = self.db['captures']
                self.plugins = self.db['plugins']
                self.results = self.db['results']
                self.logger.info("Successfully connected to embedded database")
            else:
                # Use MongoDB if available
                try:
                    from pymongo import MongoClient
                    connection_string = f"mongodb://{self.config['host']}:{self.config['port']}"
                    if self.config['username'] and self.config['password']:
                        connection_string = f"mongodb://{self.config['username']}:{self.config['password']}@{self.config['host']}:{self.config['port']}"
                    
                    client = MongoClient(connection_string)
                    self.db = client[self.config['database']]
                    self.captures = self.db.captures
                    self.plugins = self.db.plugins
                    self.results = self.db.results
                    # Test connection
                    client.server_info()
                    self.logger.info("Successfully connected to MongoDB")
                except Exception as e:
                    self.logger.error(f"MongoDB connection failed, falling back to embedded mode: {e}")
                    return self.connect()  # Retry with embedded mode
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            return False

    def disconnect(self):
        """Close database connection"""
        if self.config['embedded_mode']:
            if self.db:
                for db in self.db.values():
                    db.close()
        else:
            if hasattr(self.db, 'client'):
                self.db.client.close()
        self.db = None
        self.captures = None
        self.plugins = None
        self.results = None

    def store_capture(self, capture_data: Dict) -> Optional[str]:
        """Store NTLM capture data"""
        try:
            capture_data['timestamp'] = datetime.now().isoformat()
            if self.config['embedded_mode']:
                doc_id = self.captures.insert(capture_data)
                return str(doc_id)
            else:
                result = self.captures.insert_one(capture_data)
                return str(result.inserted_id)
            
        except Exception as e:
            self.logger.error(f"Failed to store capture: {e}")
            return None

    def store_plugin(self, plugin_data: Dict) -> Optional[str]:
        """Store plugin information"""
        try:
            plugin_data['created_at'] = datetime.now().isoformat()
            if self.config['embedded_mode']:
                doc_id = self.plugins.insert(plugin_data)
                return str(doc_id)
            else:
                result = self.plugins.insert_one(plugin_data)
                return str(result.inserted_id)
            
        except Exception as e:
            self.logger.error(f"Failed to store plugin: {e}")
            return None

    def store_result(self, result_data: Dict) -> Optional[str]:
        """Store execution result"""
        try:
            result_data['timestamp'] = datetime.now().isoformat()
            if self.config['embedded_mode']:
                doc_id = self.results.insert(result_data)
                return str(doc_id)
            else:
                result = self.results.insert_one(result_data)
                return str(result.inserted_id)
            
        except Exception as e:
            self.logger.error(f"Failed to store result: {e}")
            return None

    def get_captures(self, query: Dict = None) -> List[Dict]:
        """Retrieve capture records with optional query"""
        try:
            if self.config['embedded_mode']:
                # Add doc_id as _id for compatibility with list_results
                all_docs = self.captures.all()
                results = []
                for doc in all_docs:
                    doc_dict = dict(doc) # Convert TinyDB Document to dict
                    doc_dict['_id'] = doc.doc_id # Add _id field
                    # Apply query filtering manually if needed
                    if query:
                        match = True
                        for key, value in query.items():
                            if key not in doc_dict or doc_dict[key] != value:
                                match = False
                                break
                        if match:
                            results.append(doc_dict)
                    else:
                        results.append(doc_dict)
                return results
            else:
                return list(self.captures.find(query or {}))
        except Exception as e:
            self.logger.error(f"Failed to retrieve captures: {e}")
            return []

    def get_plugins(self, query: Dict = None) -> List[Dict]:
        """Retrieve plugin records with optional query"""
        try:
            if self.config['embedded_mode']:
                if query:
                    return self.plugins.search(Query().fragment(query))
                return self.plugins.all()
            else:
                return list(self.plugins.find(query or {}))
        except Exception as e:
            self.logger.error(f"Failed to retrieve plugins: {e}")
            return []

    def get_results(self, query: Dict = None) -> List[Dict]:
        """Retrieve result records with optional query"""
        try:
            if self.config['embedded_mode']:
                if query:
                    return self.results.search(Query().fragment(query))
                return self.results.all()
            else:
                return list(self.results.find(query or {}))
        except Exception as e:
            self.logger.error(f"Failed to retrieve results: {e}")
            return []

    def update_capture(self, capture_id: str, update_data: Dict) -> bool:
        """Update a capture record"""
        try:
            if self.config['embedded_mode']:
                self.captures.update(update_data, doc_ids=[int(capture_id)])
                return True
            else:
                from bson.objectid import ObjectId
                result = self.captures.update_one(
                    {'_id': ObjectId(capture_id)},
                    {'$set': update_data}
                )
                return result.modified_count > 0
        except Exception as e:
            self.logger.error(f"Failed to update capture: {e}")
            return False

    def delete_capture(self, capture_id: str) -> bool:
        """Delete a capture record"""
        try:
            if self.config['embedded_mode']:
                self.captures.remove(doc_ids=[int(capture_id)])
                return True
            else:
                from bson.objectid import ObjectId
                result = self.captures.delete_one({'_id': ObjectId(capture_id)})
                return result.deleted_count > 0
        except Exception as e:
            self.logger.error(f"Failed to delete capture: {e}")
            return False