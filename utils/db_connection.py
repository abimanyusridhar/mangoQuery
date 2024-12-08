from pymongo import MongoClient
import os
import json
import logging

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

client = None  # Global MongoDB client object


def connect_to_db(db_details):
    """
    Connect to a MongoDB database or process data from a JSON file.

    Parameters:
    db_details (dict): Connection details:
        - 'type': must be 'mongodb' or 'json'
        - 'host': MongoDB host (default 'localhost') (only for 'mongodb')
        - 'port': MongoDB port (default 27017) (only for 'mongodb')
        - 'database': Name of the database (only for 'mongodb')
        - 'file_path': Path to the JSON file (only for 'json')

    Returns:
    bool: True if the connection or processing is successful, False otherwise.
    """
    try:
        db_type = db_details.get('type')

        if db_type == 'mongodb':
            return connect_to_mongodb(db_details)
        elif db_type == 'json':
            return process_json_file(db_details.get('file_path'))
        else:
            raise ValueError("Unsupported database type. Choose 'mongodb' or 'json'.")

    except Exception as e:
        logging.error(f"Error in `connect_to_db`: {e}")
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

        client = MongoClient(host=host, port=port)
        client.admin.command('ping')  # Test the connection
        logging.info(f"Connected to MongoDB server at {host}:{port}")
        logging.info(f"Connected to database: {database}")
        return True

    except Exception as e:
        logging.error(f"MongoDB Connection Error: {e}")
        return False


def process_json_file(file_path):
    """
    Process and load data from a JSON file into a mock database.

    Parameters:
    file_path (str): Path to the .json file.

    Returns:
    bool: True if processed successfully, False otherwise.
    """
    try:
        # Validate file existence and type
        if not file_path or not os.path.exists(file_path):
            raise ValueError("Invalid file path. File does not exist.")
        if not file_path.endswith('.json'):
            raise ValueError("Unsupported file type. Only .json files are allowed.")

        # Load JSON content
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Validate and log each collection
        for collection_name, collection_data in data.items():
            if not isinstance(collection_data, list):
                raise ValueError(f"Collection '{collection_name}' must be a list of documents.")
            logging.info(f"Loaded collection '{collection_name}' with {len(collection_data)} documents.")

        logging.info(f"Data from '{file_path}' processed successfully.")
        return True

    except json.JSONDecodeError as e:
        logging.error(f"JSON Parsing Error in '{file_path}': {e}")
        return False
    except Exception as e:
        logging.error(f"Error processing JSON file '{file_path}': {e}")
        return False


def get_connection():
    """
    Get the active MongoDB client.

    Returns:
    MongoClient: The MongoDB client object if connected, otherwise None.
    """
    global client
    if client:
        return client
    else:
        logging.warning("No active MongoDB connection. Use `connect_to_db` to establish a connection.")
        return None


# Workflow Example
if __name__ == "__main__":
    # MongoDB Example
    mongodb_details = {
        "type": "mongodb",
        "host": "localhost",
        "port": 27017,
        "database": "test_db"
    }

    if connect_to_db(mongodb_details):
        logging.info("MongoDB connection successful. Proceeding with further operations.")
    else:
        logging.error("Failed to connect to MongoDB.")

    # JSON Example
    json_details = {
        "type": "json",
        "file_path": "example.json"  # Ensure this file exists in your project directory
    }

    if connect_to_db(json_details):
        logging.info("JSON file processed successfully. Data is ready for use.")
    else:
        logging.error("Failed to process the JSON file.")
