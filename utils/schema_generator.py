from pymongo import MongoClient
from collections import defaultdict
from pyvis.network import Network
import json
import os

client = None  # Global MongoDB client object


def connect_to_db(db_details: dict):
    """
    Connect to a MongoDB instance.

    Parameters:
    db_details (dict): MongoDB connection details with:
        - type: 'mongodb'
        - host: MongoDB host (default 'localhost')
        - port: MongoDB port (default 27017)
        - database: Database name to connect to

    Returns:
    Database object if successful, None otherwise.
    """
    global client
    try:
        if db_details.get("type") != "mongodb":
            raise ValueError("Unsupported database type. Only MongoDB is supported.")

        host = db_details.get("host", "localhost")
        port = db_details.get("port", 27017)
        client = MongoClient(host=host, port=port)

        # Ping the MongoDB server
        client.admin.command("ping")
        print(f"Connected to MongoDB server at {host}:{port}")

        db_name = db_details.get("database")
        if not db_name:
            raise ValueError("Database name is required.")

        db = client[db_name]
        print(f"Connected to MongoDB database '{db_name}' successfully.")
        return db
    except Exception as e:
        print(f"Error: Unable to connect to database. Details: {e}")
        return None


def process_external_file(file_path: str, db):
    """
    Process an external MongoDB data file and load its content into the database.

    Parameters:
    file_path (str): Path to the .js or .json file.
    db (Database): The MongoDB database object to load data into.

    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            file_content = file.read().replace("db.", "").strip()
            collections = [
                line.strip() for line in file_content.split(";") if line.strip()
            ]

            for collection_data in collections:
                if ".insert(" in collection_data:
                    collection_name, json_data = collection_data.split(".insert(", 1)
                    collection_name = collection_name.strip()
                    json_data = json.loads(json_data.strip())

                    collection = db[collection_name]
                    collection.insert_many(
                        json_data if isinstance(json_data, list) else [json_data]
                    )
                    print(f"Data from '{file_path}' imported into '{collection_name}'.")
    except json.JSONDecodeError as e:
        print(f"JSON Parsing Error: {e}")
    except Exception as e:
        print(f"Error processing external file: {e}")


def generate_schema(db):
    """
    Generate a schema for the MongoDB database.

    Parameters:
    db (Database): The MongoDB database object.

    Returns:
    dict: A schema containing collection names, fields, and sample data.
    """
    try:
        schema = {}
        for collection_name in db.list_collection_names():
            collection = db[collection_name]
            sample_data = collection.find_one() or {}
            schema[collection_name] = {
                "fields": list(sample_data.keys()),
                "sample": sample_data,
            }
        print("Schema generation successful.")
        return schema
    except Exception as e:
        print(f"Error generating schema: {e}")
        return None


def get_schema_details(schema: dict):
    """
    Extract detailed schema information, including inferred relationships.

    Parameters:
    schema (dict): The generated schema.

    Returns:
    tuple: 
        - collections (dict): Collection details with fields and data types.
        - relationships (dict): Inferred relationships between collections.
    """
    collections = {}
    relationships = defaultdict(list)
    try:
        for collection_name, details in schema.items():
            fields = details.get("fields", [])
            sample = details.get("sample", {})
            field_types = {field: type(value).__name__ for field, value in sample.items()}
            collections[collection_name] = {"fields": fields, "field_types": field_types}

            # Identify relationships (basic reference detection)
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
        print("Schema details extraction successful.")
        return collections, dict(relationships)
    except Exception as e:
        print(f"Error extracting schema details: {e}")
        return collections, dict(relationships)


def visualize_schema(schema: dict, relationships: dict):
    """
    Visualize the MongoDB schema and relationships using PyVis.

    Parameters:
    schema (dict): Collection details with fields and types.
    relationships (dict): Inferred relationships between collections.
    """
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

        output_file = "schema_visualization.html"
        net.show(output_file)
        print(f"Schema visualization saved as '{output_file}'.")
    except Exception as e:
        print(f"Error visualizing schema: {e}")


# Main Execution Flow
if __name__ == "__main__":
    db_details = {
        "type": "mongodb",
        "host": "localhost",
        "port": 27017,
        "database": "test_db",
    }
    db = connect_to_db(db_details)
    if db:
        schema = generate_schema(db)
        if schema:
            collections, relationships = get_schema_details(schema)
            visualize_schema(collections, relationships)
        else:
            print("Failed to generate schema.")
    else:
        print("Failed to connect to the database.")
