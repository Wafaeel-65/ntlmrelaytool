import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.utils.db_handler import DatabaseHandler

def test_connection():
    try:
        with DatabaseHandler() as db:
            print("Initializing database...")
            if db.initialize_database():
                print("✓ Database initialized successfully")
                print("Testing connection...")
                if db.is_connected():
                    print("✓ Database connection successful!")
                    return True
                else:
                    print("✗ Database connection failed!")
                    return False
            else:
                print("✗ Database initialization failed!")
                return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)