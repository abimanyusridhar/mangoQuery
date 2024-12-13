from pymongo import MongoClient
import os
import json
import logging
from typing import Optional, Dict, Any

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

client = None  # Global MongoDB client object

def connect_to_db(db_details: Dict[str, Any]) -> bool:
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
            file_path = db_details.get('file_path')
            if not file_path:
                raise ValueError("File path must be provided for JSON data.")
            return process_json_file(file_path)
        else:
            raise ValueError("Unsupported database type. Choose 'mongodb' or 'json'.")

    except Exception as e:
        logging.error(f"Error in `connect_to_db`: {e}")
        return False

def connect_to_mongodb(db_details: Dict[str, Any]) -> bool:
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

        # Optional: Log collections and their document counts
        db = client[database]
        collections = db.list_collection_names()
        logging.info(f"Found {len(collections)} collections in the database.")
        for collection in collections:
            count = db[collection].count_documents({})
            logging.info(f"Collection '{collection}' has {count} documents.")

        return True

    except Exception as e:
        logging.error(f"MongoDB Connection Error: {e}")
        return False

def process_json_file(file_path: str) -> bool:
    """
    Process and load data from a JSON file.

    Parameters:
    file_path (str): Path to the .json file.

    Returns:
    bool: True if processed successfully, False otherwise.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.endswith('.json'):
            raise ValueError("Unsupported file type. Only .json files are allowed.")

        # Load JSON content
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Invalid JSON format. Root element must be a JSON object.")

        total_docs = 0
        unique_fields = set()
        for collection_name, collection_data in data.items():
            if not isinstance(collection_data, list):
                raise ValueError(f"Collection '{collection_name}' must be a list of documents.")

            logging.info(f"Loaded collection '{collection_name}' with {len(collection_data)} documents.")
            total_docs += len(collection_data)
            for doc in collection_data:
                unique_fields.update(doc.keys())

        logging.info(f"Processed {len(data)} collections with a total of {total_docs} documents.")
        logging.info(f"Unique fields across collections: {len(unique_fields)}")
        return True

    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        logging.error(f"Error processing JSON file '{file_path}': {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return False

def get_connection() -> Optional[MongoClient]:
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

def generate_schema(db) -> Dict[str, Any]:
    """
    Generate a schema for the MongoDB database.

    Parameters:
    db (Database): MongoDB database object.

    Returns:
    dict: Schema containing collection names, fields, sample data, and statistics.
    """
    schema = {}
    try:
        for collection_name in db.list_collection_names():
            collection = db[collection_name]
            sample_data = collection.find_one() or {}
            total_documents = collection.count_documents({})

            # Get average document size
            avg_document_size_cursor = collection.aggregate([{
                "$group": {"_id": None, "avgSize": {"$avg": {"$bsonSize": "$$ROOT"}}}
            }])
            avg_document_size = next(avg_document_size_cursor, {}).get("avgSize", 0) / 1024  # Convert bytes to KB

            # Collect indexes
            indexes = collection.index_information()
            index_info = [{"name": index, "fields": info["key"]} for index, info in indexes.items()]

            # Identify nullable fields
            nullable_fields = [field for field, value in sample_data.items() if value is None]

            schema[collection_name] = {
                "fields": list(sample_data.keys()),
                "sample": sample_data,
                "total_documents": total_documents,
                "avg_document_size": avg_document_size,
                "nullable_fields": nullable_fields,
                "indexes": index_info,
            }

        logging.info("Schema generation successful.")
        return schema

    except Exception as e:
        logging.error(f"Error generating schema: {e}")
        return {}

# Workflow Example
if __name__ == "__main__":
    # MongoDB connection example
    mongodb_details = {
        "type": "mongodb",
        "host": "localhost",
        "port": 27017,
        "database": "test_db"
    }

    if connect_to_db(mongodb_details):
        logging.info("MongoDB connection successful. Proceeding with further operations.")
        db = get_connection()[mongodb_details["database"]]
        schema = generate_schema(db)
        if schema:
            logging.info(f"Generated schema: {json.dumps(schema, indent=2)}")
        else:
            logging.error("Schema generation failed.")
    else:
        logging.error("Failed to connect to MongoDB.")

    # JSON file processing example
    json_details = {
        "type": "json",
        "file_path": "example.json"
    }

    if connect_to_db(json_details):
        logging.info("JSON file processed successfully.")
    else:
        logging.error("Failed to process the JSON file.")
