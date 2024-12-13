from pymongo import MongoClient
from collections import defaultdict
from pyvis.network import Network
import logging
from datetime import datetime
from bson import ObjectId, DBRef

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global MongoDB client
client = None

# MongoDB connection defaults
DEFAULT_MONGODB_HOST = "localhost"
DEFAULT_MONGODB_PORT = 27017

def connect_to_db(db_details):
    """Connect to a MongoDB database."""
    global client
    try:
        if db_details.get("type") != "mongodb":
            raise ValueError("Unsupported database type. Only MongoDB is supported.")

        host = db_details.get("host", DEFAULT_MONGODB_HOST)
        port = db_details.get("port", DEFAULT_MONGODB_PORT)

        client = MongoClient(host=host, port=port)
        client.admin.command("ping")  # Test the connection
        logging.info(f"Connected to MongoDB server at {host}:{port}")

        db_name = db_details.get("database")
        if not db_name:
            raise ValueError("Database name is required.")

        db = client[db_name]
        logging.info(f"Connected to MongoDB database '{db_name}' successfully.")
        return db
    except Exception as e:
        logging.error(f"Error connecting to the database: {e}")
        return None

def generate_schema(db):
    """Generate schema with additional insights for visualization."""
    schema = {}
    db_details = {}
    try:
        db_stats = db.command("dbstats")
        db_details = {
            "name": db.name,
            "collections_count": len(db.list_collection_names()),
            "size_on_disk": db_stats.get("dataSize", 0)
        }

        for collection_name in db.list_collection_names():
            collection = db[collection_name]
            sample_data = collection.find_one() or {}
            total_documents = collection.count_documents({})
            avg_document_size = collection.aggregate([
                {"$group": {"_id": None, "avgSize": {"$avg": {"$bsonSize": "$$ROOT"}}}}
            ])
            avg_size = next(avg_document_size, {}).get("avgSize", 0)

            field_details = {}
            for field, value in sample_data.items():
                field_type = type(value).__name__
                distinct_values = collection.distinct(field)
                nullable_count = collection.count_documents({field: None})
                field_details[field] = {
                    "type": field_type,
                    "distinct_values_count": len(distinct_values),
                    "nullable_count": nullable_count
                }

            indexes = collection.index_information()
            index_info = [
                {"name": index_name, "fields": info["key"]}
                for index_name, info in indexes.items()
            ]

            schema[collection_name] = {
                "fields": list(sample_data.keys()),
                "field_details": field_details,
                "total_documents": total_documents,
                "avg_document_size": avg_size / 1024,  # Convert to KB
                "collection_size": db.command({"collStats": collection_name}).get("size", 0),
                "indexes": index_info
            }

        logging.info("Schema generation successful.")
        return schema, db_details
    except Exception as e:
        logging.error(f"Error generating schema: {e}")
        return schema, db_details

def extract_relationships(schema):
    """Extract relationships between collections based on schema details."""
    relationships = defaultdict(list)
    try:
        for collection_name, details in schema.items():
            for field, value in details.get("field_details", {}).items():
                if isinstance(value, dict) and "$ref" in value and "$id" in value:
                    ref_collection = value.get("$ref")
                    relationships[ref_collection].append(
                        {
                            "from_collection": collection_name,
                            "field": field,
                            "referenced_id": value.get("$id")
                        }
                    )
        logging.info("Relationships successfully extracted.")
    except Exception as e:
        logging.warning(f"Error extracting relationships: {e}")
    return dict(relationships)

def visualize_schema(schema, relationships, db_details, output_file=None):
    """Visualize the MongoDB schema and relationships using PyVis."""
    if not output_file:
        output_file = f"schema_visualization_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    net = Network(height="750px", width="100%", directed=True)
    try:
        for collection, details in schema.items():
            if not details.get("fields"):
                continue

            collection_label = (
                f"{collection}\nDocuments: {details['total_documents']}\nAvg Size: "
                f"{details['avg_document_size']:.2f} KB\nSize: {details['collection_size']} bytes"
            )
            net.add_node(collection, label=collection_label, shape="ellipse", color="#76c7c0")

            for field, field_info in details.get("field_details", {}).items():
                field_node = f"{collection}.{field}"
                net.add_node(
                    field_node,
                    label=(
                        f"{field} ({field_info['type']})\nDistinct: {field_info['distinct_values_count']}\n"
                        f"Nullable: {field_info['nullable_count']}"
                    ),
                    shape="box",
                    color="#f39c12"
                )
                net.add_edge(collection, field_node, color="#3498db")

        for ref_collection, refs in relationships.items():
            for ref in refs:
                net.add_edge(
                    ref["from_collection"],
                    ref_collection,
                    label=f"Ref: {ref['field']}",
                    color="#e74c3c"
                )

        db_info_node = "Database Info"
        db_info_label = (
            f"{db_details['name']}\nCollections: {db_details['collections_count']}\n"
            f"Size on Disk: {db_details['size_on_disk']} bytes"
        )
        net.add_node(db_info_node, label=db_info_label, shape="box", color="#2ecc71")
        net.add_edge(db_info_node, list(schema.keys())[0], label="Contains", color="#2ecc71")

        net.show(output_file)
        logging.info(f"Schema visualization saved as '{output_file}'.")
    except Exception as e:
        logging.error(f"Error visualizing schema: {e}")

if __name__ == "__main__":
    db_details = {
        "type": "mongodb",
        "host": DEFAULT_MONGODB_HOST,
        "port": DEFAULT_MONGODB_PORT,
        "database": "test_db"
    }
    db = connect_to_db(db_details)

    if db:
        schema, db_details = generate_schema(db)
        if schema:
            relationships = extract_relationships(schema)
            visualize_schema(schema, relationships, db_details)
        else:
            logging.error("Failed to generate schema.")
    else:
        logging.error("Failed to connect to the database.")
