from flask import Flask, render_template, request, redirect, url_for, flash, session
from transformers import pipeline
import os
import json
import pymongo
from bson import ObjectId, DBRef
from werkzeug.utils import secure_filename
import logging

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secret_key")

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Folder for uploaded databases
UPLOAD_FOLDER = 'uploaded_databases'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# NLP Model for MongoDB query generation
try:
    logging.info("Loading NLP model...")
    nlp_model = pipeline('text2text-generation', model="t5-large")
    logging.info("NLP model loaded successfully.")
except Exception as e:
    logging.error(f"Error loading NLP model: {e}")
    nlp_model = None

# Helper Functions

def serialize_schema(schema):
    """Serialize schema and handle MongoDB-specific types."""
    serialized_schema = {}
    for collection, details in schema.items():
        sample = details.get("sample", {})
        serialized_schema[collection] = {
            "fields": details["fields"],
            "field_types": details.get("field_types", {}),
            "sample": {
                key: (str(value) if isinstance(value, (ObjectId, DBRef)) else value)
                for key, value in sample.items()
            },
            "total_documents": details.get("total_documents", 0),
            "avg_document_size": details.get("avg_document_size", 0),
            "nullable_fields": details.get("nullable_fields", []),
            "indexes": details.get("indexes", []),
        }
    return serialized_schema

def generate_schema(data):
    """Generate schema from MongoDB collections or JSON data."""
    schema = {}
    try:
        if isinstance(data, dict):  # JSON data
            for collection_name, documents in data.items():
                if isinstance(documents, list) and documents:
                    first_doc = documents[0]
                    schema[collection_name] = {
                        "fields": list(first_doc.keys()),
                        "field_types": {key: type(value).__name__ for key, value in first_doc.items()},
                        "sample": first_doc,
                        "total_documents": len(documents),
                        "avg_document_size": sum(len(str(doc)) for doc in documents) / len(documents) if documents else 0,
                        "nullable_fields": [key for key, value in first_doc.items() if value is None],
                        "indexes": []  # Add logic if required for indexing (e.g., from JSON metadata)
                    }
        else:  # MongoDB data
            for collection_name in data.list_collection_names():
                collection = data[collection_name]
                sample_data = collection.find_one() or {}
                total_documents = collection.count_documents({})
                avg_size = collection.aggregate([{"$group": {"_id": None, "avgSize": {"$avg": {"$bsonSize": "$$ROOT"}}}}])
                avg_document_size = next(avg_size, {}).get("avgSize", 0)
                
                # Extract indexes
                indexes = collection.index_information()
                schema[collection_name] = {
                    "fields": list(sample_data.keys()),
                    "field_types": {key: type(value).__name__ for key, value in sample_data.items()},
                    "sample": sample_data,
                    "total_documents": total_documents,
                    "avg_document_size": avg_document_size / 1024,  # Convert bytes to KB
                    "nullable_fields": [key for key, value in sample_data.items() if value is None],
                    "indexes": [{"name": index_name, "fields": index_info["key"]} for index_name, index_info in indexes.items()]
                }
        logging.info("Schema generation successful.")
        return schema
    except Exception as e:
        logging.error(f"Error generating schema: {e}")
        raise RuntimeError(f"Error generating schema: {e}")

def generate_mongo_query(natural_language_query, schema):
    """Convert natural language query into a MongoDB query."""
    try:
        if not nlp_model:
            raise RuntimeError("NLP model not loaded.")
        schema_context = json.dumps(schema, indent=2)
        prompt = f"Schema:\n{schema_context}\n\nQuery: {natural_language_query}\n\nMongoDB Query:"
        result = nlp_model(prompt, max_length=200, num_return_sequences=1)
        return json.loads(result[0]['generated_text'].strip())
    except Exception as e:
        logging.error(f"Error generating MongoDB query: {e}")
        return None

def execute_query_with_mongo_query(mongo_query):
    """Execute a MongoDB query and return results."""
    selected_db = session.get('selected_db')
    try:
        if selected_db and selected_db['type'] == 'mongodb':
            client = pymongo.MongoClient(selected_db['host'], selected_db['port'])
            db = client[selected_db['database']]
            collection = db[mongo_query['collection']]
            query_filter = mongo_query.get('filter', {})
            projection = mongo_query.get('projection')
            result = collection.find(query_filter, projection)
            return [
                {key: (str(value) if isinstance(value, (ObjectId, DBRef)) else value) for key, value in doc.items()}
                for doc in result
            ], None
        return None, 'Unsupported database type.'
    except Exception as e:
        logging.error(f"Error executing MongoDB query: {e}")
        return None, str(e)

# Routes

@app.route('/')
def index():
    """Render homepage."""
    return render_template('index.html')

@app.route('/select_db', methods=['GET', 'POST'])
def select_db():
    """Handle database selection or file upload."""
    if request.method == 'POST':
        db_type = request.form.get('db_type')

        if db_type == 'mongodb':
            host = request.form.get('host', 'localhost')
            port = int(request.form.get('port', 27017))
            database = request.form.get('database')
            if not database:
                flash('Please provide a database name.', 'danger')
                return redirect(url_for('select_db'))
            session['selected_db'] = {'type': 'mongodb', 'host': host, 'port': port, 'database': database}
            flash('MongoDB connection details saved.', 'success')
            return redirect(url_for('connect_database'))

        elif db_type == 'json_or_js':
            file = request.files.get('db_file')
            if file and file.filename.endswith(('.json', '.js')):
                try:
                    file_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
                    file.save(file_path)
                    session['selected_db'] = {'type': 'json', 'file_path': file_path}
                    flash('JSON/JS file uploaded successfully.', 'success')
                    return redirect(url_for('connect_database'))
                except Exception as e:
                    flash(f'Error uploading file: {e}', 'danger')
            else:
                flash('Invalid or missing file. Please upload a valid JSON/JS file.', 'danger')
        else:
            flash('Unsupported database type selected.', 'danger')
    return render_template('select_db.html')

@app.route('/connect', methods=['GET'])
def connect_database():
    """Connect to the selected database."""
    selected_db = session.get('selected_db')
    if not selected_db:
        flash('No database selected. Please select a database first.', 'danger')
        return redirect(url_for('select_db'))

    try:
        if selected_db['type'] == 'mongodb':
            client = pymongo.MongoClient(selected_db['host'], selected_db['port'])
            db = client[selected_db['database']]
            schema = generate_schema(db)
        elif selected_db['type'] == 'json':
            file_path = selected_db.get('file_path')
            with open(file_path, 'r') as file:
                data = json.load(file)
                schema = generate_schema(data)
        else:
            raise ValueError("Unsupported database type.")
        session['schema'] = serialize_schema(schema)
        return render_template('schema.html', collections=session['schema'])
    except Exception as e:
        logging.error(f"Error connecting to database: {e}")
        flash(f"Error: {e}", 'danger')
        return redirect(url_for('select_db'))

@app.route('/nlp_query', methods=['GET', 'POST'])
def nlp_query():
    """Process natural language queries."""
    if request.method == 'POST':
        nl_query = request.form.get('nl_query', '').strip()
        if not nl_query:
            flash('Query cannot be empty.', 'danger')
            return redirect(url_for('nlp_query'))
        try:
            mongo_query = generate_mongo_query(nl_query, session.get('schema', {}))
            result, error = execute_query_with_mongo_query(mongo_query)
            if error:
                flash(error, 'danger')
            return render_template('result.html', result=result)
        except Exception as e:
            flash(f"Error processing query: {e}", 'danger')
    return render_template('nlp_query.html')

# Main
if __name__ == "__main__":
    app.run(debug=True)
