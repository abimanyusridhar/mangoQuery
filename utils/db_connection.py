from pymongo import MongoClient
import os
import json

client = None  # Global MongoDB client object

def connect_to_db(db_details):
    """
    Connect to a MongoDB database or load data from an external .js or .json file.

    Parameters:
    db_details (dict): A dictionary containing connection details:
                       - 'type': must be 'mongodb' or 'json'
                       - 'host': MongoDB host (default 'localhost') (only for 'mongodb')
                       - 'port': MongoDB port (default 27017) (only for 'mongodb')
                       - 'database': Name of the database to connect to (only for 'mongodb')
                       - 'file_path': Path to an external .js or .json file (only for 'json')

    Returns:
    bool: True if connection is successful or file is processed successfully, False otherwise.
    """
    global client
    try:
        db_type = db_details.get('type')

        if db_type == 'mongodb':
            return connect_to_mongodb(db_details)
        elif db_type == 'json':
            return process_json_file(db_details.get('file_path'))
        else:
            raise ValueError("Unsupported database type. Please choose either 'mongodb' or 'json'.")

    except ValueError as e:
        print(f"Error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        return False

def connect_to_mongodb(db_details):
    """
    Connect to a MongoDB instance.

    Parameters:
    db_details (dict): MongoDB connection details.

    Returns:
    bool: True if connected successfully, False otherwise.
    """
    global client
    try:
        host = db_details.get('host', 'localhost')
        port = db_details.get('port', 27017)
        database = db_details.get('database')

        if not database:
            raise ValueError("Database name is required for MongoDB connection.")

        # Establish connection to MongoDB
        client = MongoClient(host=host, port=port)
        client.admin.command('ping')  # Test connection
        print(f"Connected to MongoDB server at {host}:{port}")
        print(f"Database '{database}' connection successful.")
        return True

    except ValueError as e:
        print(f"MongoDB Connection Error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected MongoDB Connection Error: {e}")
        return False

def process_json_file(file_path):
    """
    Process and load data from a JSON file into a mock database.

    Parameters:
    file_path (str): Path to the .json or .js file.

    Returns:
    bool: True if processed successfully, False otherwise.
    """
    try:
        if not file_path or not os.path.exists(file_path):
            raise ValueError("Invalid file path. File does not exist.")
        if not (file_path.endswith('.json') or file_path.endswith('.js')):
            raise ValueError("Unsupported file type. Only .json or .js files are allowed.")

        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

            for collection_name, collection_data in data.items():
                print(f"Loading collection '{collection_name}' with {len(collection_data)} documents.")
                # Mock insertion or optional real MongoDB insertion
                # Example: client['mock_db'][collection_name].insert_many(collection_data)

            print(f"Data from '{file_path}' successfully loaded.")
            return True

    except json.JSONDecodeError as e:
        print(f"JSON Parsing Error: {e}")
        return False
    except ValueError as e:
        print(f"File Error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error while processing JSON file: {e}")
        return False

def get_connection():
    """
    Returns the active MongoDB client.

    Returns:
    MongoClient: The MongoDB client object if connected, otherwise None.
    """
    if client:
        return client
    else:
        print("No active MongoDB connection. Please establish a connection using `connect_to_db`.")
        return None
