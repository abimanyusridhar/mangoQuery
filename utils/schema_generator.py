from pymongo import MongoClient
from collections import defaultdict
from pyvis.network import Network
import json
import logging
from datetime import datetime
from bson import ObjectId, DBRef

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

client = None

DEFAULT_MONGODB_HOST = "localhost"
DEFAULT_MONGODB_PORT = 27017


def connect_to_db(db_details: dict):
    """Connect to MongoDB database"""
    global client
    try:
        if db_details.get("type") != "mongodb":
            raise ValueError("Unsupported database type. Only MongoDB is supported.")
        
        host = db_details.get("host", DEFAULT_MONGODB_HOST)
        port = db_details.get("port", DEFAULT_MONGODB_PORT)
        client = MongoClient(host=host, port=port)
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


def generate_schema(db):
    """Generate schema with additional insights for visualization"""
    schema = {}
    try:
        for collection_name in db.list_collection_names():
            collection = db[collection_name]
            sample_data = collection.find_one() or {}
            total_documents = collection.count_documents({})
            avg_document_size = collection.aggregate([
                {"$group": {"_id": None, "avgSize": {"$avg": {"$bsonSize": "$$ROOT"}}}}])
            avg_size = next(avg_document_size, {}).get("avgSize", 0)

            # Extract field-level insights
            field_details = {}
            for field, value in sample_data.items():
                field_type = type(value).__name__
                distinct_values = collection.distinct(field)
                field_details[field] = {
                    "type": field_type,
                    "distinct_values_count": len(distinct_values),
                }

            schema[collection_name] = {
                "fields": list(sample_data.keys()),
                "field_details": field_details,
                "total_documents": total_documents,
                "avg_document_size": avg_size / 1024,  # Convert bytes to KB
            }
        logging.info("Schema generation successful.")
        return schema
    except Exception as e:
        logging.error(f"Error generating schema: {e}")
        return schema


def get_schema_details(schema: dict):
    """Extract detailed schema information including inferred relationships."""
    collections = {}
    relationships = defaultdict(list)
    try:
        for collection_name, details in schema.items():
            fields = details.get("fields", [])
            field_details = details.get("field_details", {})
            collections[collection_name] = {
                "fields": fields,
                "field_details": field_details,
                "total_documents": details["total_documents"],
                "avg_document_size": details["avg_document_size"],
            }

            # Look for relationships based on "$ref" fields
            for field, value in field_details.items():
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
    """Visualize the MongoDB schema and relationships using PyVis"""
    if not output_file:
        output_file = f"schema_visualization_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    net = Network(height="750px", width="100%", directed=True)
    try:
        # Add nodes for collections and fields with insights
        for collection, details in schema.items():
            collection_label = (
                f"{collection}\nDocuments: {details['total_documents']}\nAvg Size: "
                f"{details['avg_document_size']:.2f} KB"
            )
            net.add_node(collection, label=collection_label, shape="ellipse", color="#76c7c0")
            for field, field_info in details["field_details"].items():
                field_node = f"{collection}.{field}"
                net.add_node(
                    field_node,
                    label=f"{field} ({field_info['type']})\nDistinct Values: {field_info['distinct_values_count']}",
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
