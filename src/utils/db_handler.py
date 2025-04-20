import os
import sys
import sqlite3
from datetime import datetime
from typing import Optional, List, Any, Dict, Tuple

# Add project root to path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.modules.storage.models import Plugin, Utilisateur, Execute, Resultat

def adapt_datetime(val):
    """Convert datetime to SQLite TEXT"""
    return val.strftime("%Y-%m-%d %H:%M:%S") if val else None

def convert_datetime(val):
    """Convert SQLite TEXT to datetime"""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, bytes):
        val = val.decode()
    try:
        return datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None

# Register the adapter and converter
sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_datetime)

class DatabaseHandler:
    def __init__(self, db_path: str = "ntlm_relay.db"):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
        
    def connect(self) -> bool:
        """Establish database connection"""
        try:
            if not self.connection:
                self.connection = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
                self.cursor = self.connection.cursor()
                return self.initialize_database()
            return True
        except sqlite3.Error as e:
            print(f"Database connection failed: {e}")
            return False

    def disconnect(self) -> None:
        if self.connection:
            self.connection.close()
            self.connection = None
            self.cursor = None

    def test_connection(self) -> bool:
        """Test if database connection is active"""
        try:
            if self.connection:
                self.cursor.execute("SELECT 1")
                return True
            return False
        except (sqlite3.Error, AttributeError):
            return False

    def initialize_database(self) -> bool:
        """Initialize the SQLite database with required tables."""
        try:
            if not self.test_connection():
                if not self.connect():
                    raise Exception("Could not establish database connection")
            
            # Create tables in correct order (parent tables first)
            create_tables = [
                """CREATE TABLE IF NOT EXISTS UTILISATEUR (
                    ID_UTILISATEUR INTEGER PRIMARY KEY AUTOINCREMENT,
                    PRENOM_UTILISATEUR TEXT,
                    ROLE_UTILISATEUR TEXT,
                    EMAIL_UTILISATEUR TEXT,
                    DERNIERE_CONNEXION TIMESTAMP
                )""",
                """CREATE TABLE IF NOT EXISTS PLUGIN (
                    ID_PLUGIN INTEGER PRIMARY KEY AUTOINCREMENT,
                    NOM_PLUGIN TEXT,
                    DATE_CREATION TIMESTAMP,
                    DESCRIPTION TEXT,
                    VERSION TEXT,
                    NTLM_KEY TEXT
                )""",
                """CREATE TABLE IF NOT EXISTS RESULTAT (
                    ID_RESULTAT INTEGER PRIMARY KEY AUTOINCREMENT,
                    ID_PLUGIN INTEGER NOT NULL,
                    DATE_RESULTAT TIMESTAMP,
                    STATUT TEXT,
                    DETAILS TEXT,
                    FOREIGN KEY (ID_PLUGIN) REFERENCES PLUGIN(ID_PLUGIN)
                )""",
                """CREATE TABLE IF NOT EXISTS EXECUTE (
                    ID_UTILISATEUR INTEGER NOT NULL,
                    ID_PLUGIN INTEGER NOT NULL,
                    DATE_EXECUTION TIMESTAMP,
                    PRIMARY KEY (ID_UTILISATEUR, ID_PLUGIN),
                    FOREIGN KEY (ID_UTILISATEUR) REFERENCES UTILISATEUR(ID_UTILISATEUR),
                    FOREIGN KEY (ID_PLUGIN) REFERENCES PLUGIN(ID_PLUGIN)
                )"""
            ]
            
            for create_command in create_tables:
                self.cursor.execute(create_command)
            
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"Database initialization failed: {e}")
            return False

    def execute_query(self, query: str, params: Tuple = ()) -> Optional[List[Any]]:
        try:
            if not self.test_connection():
                if not self.connect():
                    raise Exception("Could not establish database connection")
            self.cursor.execute(query, params)
            self.connection.commit()
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            raise Exception(f"Query execution failed: {e}")

    def add_plugin(self, plugin_name: str, description: str, version: str, ntlm_key: str) -> None:
        query = """
        INSERT INTO plugins (nom_plugin, description, version, ntlm_key, date_creation)
        VALUES (?, ?, ?, ?, ?)
        """
        self.execute_query(query, (plugin_name, description, version, ntlm_key, datetime.now()))

    def get_plugin_by_id(self, plugin_id: int) -> Optional[Dict[str, Any]]:
        try:
            query = "SELECT * FROM plugins WHERE id = ?"
            result = self.execute_query(query, (plugin_id,))
            if result and len(result) > 0:
                return {
                    "id": result[0][0],
                    "nom_plugin": result[0][1],
                    "description": result[0][2],
                    "version": result[0][3],
                    "ntlm_key": result[0][4],
                    "date_creation": result[0][5]
                }
            return None
        except sqlite3.Error as e:
            raise Exception(f"Failed to get plugin: {e}")

    def get_user_plugins(self, user_id: int) -> List[Dict[str, Any]]:
        try:
            query = "SELECT * FROM plugins WHERE user_id = ?"
            results = self.execute_query(query, (user_id,))
            return [{
                "id": row[0],
                "nom_plugin": row[1],
                "description": row[2],
                "version": row[3],
                "ntlm_key": row[4],
                "date_creation": row[5]
            } for row in results] if results else []
        except sqlite3.Error as e:
            raise Exception(f"Failed to get user plugins: {e}")

    def store_plugin(self, nom_plugin, description, version, ntlm_key):
        """Store plugin data with automatic reconnection"""
        try:
            if not self.test_connection():
                if not self.connect():
                    raise Exception("Could not establish database connection")
                    
            query = """INSERT INTO PLUGIN 
                      (NOM_PLUGIN, DATE_CREATION, DESCRIPTION, VERSION, NTLM_KEY) 
                      VALUES (?, ?, ?, ?, ?)"""
            values = (nom_plugin, datetime.now(), description, version, ntlm_key)
            self.cursor.execute(query, values)
            self.connection.commit()
            return self.cursor.lastrowid
            
        except sqlite3.Error as err:
            print(f"Error storing plugin: {err}")
            self.disconnect()  # Force reconnection on next attempt
            return None

    def store_result(self, id_plugin, status, details):
        """Store result data with automatic reconnection"""
        try:
            if not self.test_connection():
                if not self.connect():
                    raise Exception("Could not establish database connection")
                    
            query = """INSERT INTO RESULTAT 
                      (ID_PLUGIN, DATE_RESULTAT, STATUT, DETAILS) 
                      VALUES (?, ?, ?, ?)"""
            values = (id_plugin, datetime.now(), status, details)
            self.cursor.execute(query, values)
            self.connection.commit()
            return True
            
        except sqlite3.Error as err:
            print(f"Error storing result: {err}")
            self.disconnect()  # Force reconnection on next attempt
            return False

    def record_execution(self, id_utilisateur, id_plugin):
        """
        Record the execution of a plugin by a user in the database.

        Args:
            id_utilisateur (int): The ID of the user who executed the plugin.
            id_plugin (int): The ID of the plugin that was executed.

        Returns:
            bool: True if the execution was successfully recorded, False otherwise.
        """
        try:
            if not self.test_connection():
                if not self.connect():
                    raise Exception("Could not establish database connection")
                    
            query = """INSERT INTO EXECUTE 
                      (ID_UTILISATEUR, ID_PLUGIN, DATE_EXECUTION) 
                      VALUES (?, ?, ?)"""
            values = (id_utilisateur, id_plugin, datetime.now())
            self.cursor.execute(query, values)
            self.connection.commit()
            return True
        except sqlite3.Error as err:
            print(f"Error recording execution: {err}")
            self.disconnect()  # Force reconnection on next attempt
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

def test_connection():
    print("Testing database connection...")
    try:
        db = DatabaseHandler()
        success = db.test_connection()
        if success:
            print("✓ Successfully connected to database")
        else:
            print("✗ Failed to connect to database")
        db.disconnect()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"An error occurred during the connection test: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_connection()