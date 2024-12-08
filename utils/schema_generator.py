from pymongo import MongoClient
from collections import defaultdict
from pyvis.network import Network
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global MongoDB client object
client = None

DEFAULT_MONGODB_HOST = "localhost"
DEFAULT_MONGODB_PORT = 27017


def connect_to_db(db_details: dict):
    """
    Connect to a MongoDB instance.
    Parameters:
        db_details (dict): MongoDB connection details.
    Returns:
        MongoDB database object if successful, None otherwise.
    """
    global client
    try:
        if db_details.get("type") != "mongodb":
            raise ValueError("Unsupported database type. Only MongoDB is supported.")

        host = db_details.get("host", DEFAULT_MONGODB_HOST)
        port = db_details.get("port", DEFAULT_MONGODB_PORT)
        client = MongoClient(host=host, port=port)

        # Ping the MongoDB server
        client.admin.command("ping")
        logging.info(f"Connected to MongoDB server at {host}:{port}")

        db_name = db_details.get("database")
        if not db_name:
            raise ValueError("Database name is required.")

        db = client[db_name]
        logging.info(f"Connected to MongoDB database '{db_name}' successfully.")
        return db
    except Exception as e:
        logging.error(f"Error: Unable to connect to the database. Details: {e}")
        return None


def process_external_file(file_path: str, db):
    """
    Process an external MongoDB data file and load its content into the database.
    Parameters:
        file_path (str): Path to the .json file.
        db (Database): MongoDB database object to load data into.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            if not isinstance(data, dict):
                raise ValueError("Invalid file format. Root element must be a JSON object.")
            for collection_name, collection_data in data.items():
                if not isinstance(collection_data, list):
                    raise ValueError(f"Collection '{collection_name}' must be a list of documents.")
                db[collection_name].insert_many(collection_data)
                logging.info(f"Imported {len(collection_data)} documents into '{collection_name}' collection.")
    except json.JSONDecodeError as e:
        logging.error(f"JSON Parsing Error: {e}")
    except Exception as e:
        logging.error(f"Error processing external file: {e}")


def generate_schema(db):
    """
    Generate a schema for the MongoDB database.
    Parameters:
        db (Database): MongoDB database object.
    Returns:
        dict: Schema containing collection names, fields, and sample data.
    """
    schema = {}
    try:
        for collection_name in db.list_collection_names():
            collection = db[collection_name]
            sample_data = collection.find_one() or {}
            schema[collection_name] = {
                "fields": list(sample_data.keys()),
                "sample": sample_data,
            }
        logging.info("Schema generation successful.")
        return schema
    except Exception as e:
        logging.error(f"Error generating schema: {e}")
        return schema


def get_schema_details(schema: dict):
    """
    Extract detailed schema information, including inferred relationships.
    Parameters:
        schema (dict): The generated schema.
    Returns:
        tuple: Collection details with fields/types and relationships.
    """
    collections = {}
    relationships = defaultdict(list)
    try:
        for collection_name, details in schema.items():
            fields = details.get("fields", [])
            sample = details.get("sample", {})
            field_types = {field: type(value).__name__ for field, value in sample.items()}
            collections[collection_name] = {"fields": fields, "field_types": field_types}

            for field, value in sample.items():
                if isinstance(value, dict) and "$ref" in value and "$id" in value:
                    ref_collection = value.get("$ref")
                    relationships[ref_collection].append(
                        {
                            "from_collection": collection_name,
                            "field": field,
                            "referenced_id": value.get("$id"),
                        }
                    )
        logging.info("Schema details extraction successful.")
        return collections, dict(relationships)
    except Exception as e:
        logging.error(f"Error extracting schema details: {e}")
        return collections, dict(relationships)


def visualize_schema(schema: dict, relationships: dict, output_file=None):
    """
    Visualize the MongoDB schema and relationships using PyVis.
    Parameters:
        schema (dict): Collection details with fields/types.
        relationships (dict): Inferred relationships.
        output_file (str): File name for saving the visualization. Defaults to timestamp-based name.
    """
    if not output_file:
        output_file = f"schema_visualization_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    net = Network(height="750px", width="100%", directed=True)
    try:
        # Add nodes for collections and fields
        for collection, details in schema.items():
            net.add_node(
                collection, label=collection, shape="ellipse", color="#76c7c0"
            )
            for field, field_type in details["field_types"].items():
                field_node = f"{collection}.{field}"
                net.add_node(
                    field_node,
                    label=f"{field} ({field_type})",
                    shape="box",
                    color="#f39c12",
                )
                net.add_edge(collection, field_node, color="#3498db")

        # Add edges for relationships
        for ref_collection, refs in relationships.items():
            for ref in refs:
                net.add_edge(
                    ref["from_collection"],
                    ref_collection,
                    label=f"Ref: {ref['field']}",
                    color="#e74c3c",
                )

        net.show(output_file)
        logging.info(f"Schema visualization saved as '{output_file}'.")
    except Exception as e:
        logging.error(f"Error visualizing schema: {e}")


# Main Execution Flow
if __name__ == "__main__":
    db_details = {
        "type": "mongodb",
        "host": DEFAULT_MONGODB_HOST,
        "port": DEFAULT_MONGODB_PORT,
        "database": "test_db",
    }
    db = connect_to_db(db_details)
    if db:
        schema = generate_schema(db)
        if schema:
            collections, relationships = get_schema_details(schema)
            visualize_schema(collections, relationships)
        else:
            logging.error("Failed to generate schema.")
    else:
        logging.error("Failed to connect to the database.")
