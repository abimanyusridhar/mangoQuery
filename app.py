from flask import Flask, render_template, request, redirect, url_for, flash, session
from utils.db_connection import connect_to_db, get_connection
from utils.schema_generator import generate_schema, get_schema_details
from transformers import pipeline
import os
import json
import pymongo
import re

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

# Folder for uploaded databases
UPLOAD_FOLDER = 'uploaded_databases'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# NLP Model for MongoDB query generation
nlp_model = pipeline('text2text-generation', model="t5-large")

# Homepage
@app.route('/')
def index():
    """Render the homepage."""
    return render_template('index.html')

# Route to select and upload/connect to database
@app.route('/select_db', methods=['GET', 'POST'])
def select_db():
    """Allow user to upload/select a database."""
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

        elif db_type == 'json':
            file = request.files.get('json_file')
            if file and file.filename.endswith('.json'):
                file_path = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(file_path)
                session['selected_db'] = {'type': 'json', 'file_path': file_path}
                flash('JSON file uploaded successfully.', 'success')
                return redirect(url_for('connect_database'))
            else:
                flash('Invalid or missing JSON file. Please upload a valid JSON file.', 'danger')
                return redirect(url_for('select_db'))

        else:
            flash('Unsupported database type selected.', 'danger')
            return redirect(url_for('select_db'))

    return render_template('select_db.html')

# Connect to the selected database and generate schema
@app.route('/connect', methods=['GET'])
def connect_database():
    """Connect to the selected database and display the schema."""
    selected_db = session.get('selected_db')

    if not selected_db:
        flash('No database selected. Please select a database first.', 'danger')
        return redirect(url_for('select_db'))

    try:
        if selected_db['type'] == 'mongodb':
            client = pymongo.MongoClient(selected_db['host'], selected_db['port'])
            db = client[selected_db['database']]
            collections = db.list_collection_names()

            if not collections:
                flash('No collections found in the MongoDB database.', 'warning')
                return redirect(url_for('select_db'))

            schema = generate_schema(db)
            tables, relationships = get_schema_details(schema)
            session['schema'] = schema
            return render_template('schema.html', tables=tables, relationships=relationships)

        elif selected_db['type'] == 'json':
            file_path = selected_db.get('file_path')
            with open(file_path, 'r') as file:
                data = json.load(file)

            schema = generate_schema(data)
            tables, relationships = get_schema_details(schema)
            session['schema'] = schema
            return render_template('schema.html', tables=tables, relationships=relationships)

        else:
            flash('Unsupported database type selected.', 'danger')
            return redirect(url_for('select_db'))

    except Exception as e:
        flash(f"Error connecting to the database: {e}", 'danger')
        return redirect(url_for('select_db'))

# NLP Query Generation and Execution
@app.route('/nlp_query', methods=['GET', 'POST'])
def nlp_query():
    """Handle natural language queries and execute MongoDB queries."""
    selected_db = session.get('selected_db')
    schema = session.get('schema')

    if not selected_db or not schema:
        flash('No database connected. Please connect to a database first.', 'danger')
        return redirect(url_for('select_db'))

    if request.method == 'POST':
        natural_language_query = request.form.get('nl_query')

        if not natural_language_query.strip():
            flash('Query cannot be empty.', 'danger')
            return redirect(url_for('nlp_query'))

        try:
            mongo_query = generate_mongo_query(natural_language_query, schema)
            if not mongo_query:
                flash('Failed to generate a valid MongoDB query.', 'danger')
                return redirect(url_for('nlp_query'))

            result, error = execute_query_with_mongo_query(mongo_query)
            if error:
                flash(f"Error executing MongoDB query: {error}", 'danger')
                return redirect(url_for('nlp_query'))

            return render_template('result.html', result=result)

        except Exception as e:
            flash(f"Error processing query: {e}", 'danger')
            return redirect(url_for('nlp_query'))

    return render_template('nlp_query.html')

# Helper Functions
def execute_query_with_mongo_query(mongo_query):
    """Execute a MongoDB query and return results."""
    selected_db = session.get('selected_db')

    if selected_db['type'] == 'mongodb':
        try:
            client = pymongo.MongoClient(selected_db['host'], selected_db['port'])
            db = client[selected_db['database']]
            collection = db[mongo_query['collection']]
            result = collection.find(mongo_query['filter'])
            return list(result), None
        except Exception as e:
            return None, str(e)

    return None, 'Unsupported database type.'

def generate_mongo_query(natural_language_query, schema):
    """Convert a natural language query into a MongoDB query."""
    try:
        schema_context = json.dumps(schema, indent=2)
        prompt = f"Schema:\n{schema_context}\n\nQuery: {natural_language_query}\n\nMongoDB Query:"
        result = nlp_model(prompt, max_length=200, num_return_sequences=1)
        return json.loads(result[0]['generated_text'].strip())
    except Exception as e:
        return None

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
