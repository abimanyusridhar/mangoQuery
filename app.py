import os
import random
import string
import logging
import bson
from flask import Flask, json, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
import requests
from config import Config
from itsdangerous import URLSafeTimedSerializer
from transformers import pipeline
from bson import ObjectId, DBRef
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session
from werkzeug.exceptions import BadRequest
from dotenv import load_dotenv
from requests_oauthlib import OAuth2Session

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or os.urandom(24).hex()
app.config['SESSION_TYPE'] = 'redis'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app.wsgi_app = ProxyFix(
    app.wsgi_app, 
    x_for=1, 
    x_proto=1, 
    x_host=1, 
    x_prefix=1
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
db = SQLAlchemy(app)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'app_session:'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')

Session(app)

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
AUTHORIZATION_BASE_URL = 'https://accounts.google.com/o/oauth2/auth'
TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
SCOPE = ['openid', 'email', 'profile']
REDIRECT_URI = 'http://localhost:5000/callback'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DATABASE_NAME = os.getenv("DATABASE_NAME", "my_database")
USER_COLLECTION_NAME = os.getenv("USER_COLLECTION_NAME", "users")

mongo_client = MongoClient(MONGO_URI)
db = mongo_client[DATABASE_NAME]
user_collection = db[USER_COLLECTION_NAME]

class User(UserMixin):
    def __init__(self, email):
        self.email = email
        self.id = str(ObjectId())

    @classmethod
    def from_mongo(cls, mongo_data):
        user = cls(mongo_data['email'])
        user.id = str(mongo_data['_id'])
        return user

    def get_id(self):
        return self.id

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.id_attribute = "get_id"
mail = Mail(app)

from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.secret_key)

from bson import ObjectId

@login_manager.user_loader
def load_user(user_id):
    # First, try to find the user by email (for Google login)
    mongo_user = user_collection.find_one({"email": user_id})
    
    # If not found by email, try with ObjectId (for normal login)
    if mongo_user is None:
        try:
            mongo_user = user_collection.find_one({"_id": ObjectId(user_id)})
        except bson.errors.InvalidId:
            # If the user_id is neither a valid email nor ObjectId, return None
            return None

    return User.from_mongo(mongo_user) if mongo_user else None

nlp_model = None
# Initialize logging centrally
def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Stream handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # File handler
    file_handler = logging.FileHandler('app.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

logger = setup_logger()

# Initialize logging centrally
def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Stream handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # File handler
    file_handler = logging.FileHandler('app.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

logger = setup_logger()

logger = logging.getLogger(__name__)

@app.route('/login/google')
def google_login():
    try:
        google = OAuth2Session(GOOGLE_CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
        authorization_url, state = google.authorization_url(
            AUTHORIZATION_BASE_URL,
            access_type="offline",
            prompt="select_account"
        )
        session['oauth_state'] = state
        print(f"DEBUG: oauth_state set in session: {state}")  # Debug log
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"Error initiating Google login: {e}")
        flash('Failed to start Google login. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/callback')
def callback():
    print(f"DEBUG: oauth_state in session: {session.get('oauth_state')}")  # Debug log
    state = session.get('oauth_state')
    if not state:
        flash('OAuth state is missing or expired. Please try logging in again.', 'error')
        return redirect(url_for('login'))

    try:
        google = OAuth2Session(GOOGLE_CLIENT_ID, state=state, scope=SCOPE, redirect_uri=REDIRECT_URI)
        token = google.fetch_token(
            TOKEN_URL,
            client_secret=GOOGLE_CLIENT_SECRET,
            authorization_response=request.url
        )
        session['google_token'] = token

        # Fetch user info
        user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
        email = user_info.get('email')
        if not email:
            raise ValueError("Failed to retrieve email from Google.")

        # Check if user exists in database
        user = user_collection.find_one({"email": email})
        if user is None:
            # Create new user if not found
            new_user = User(email=email)
            user_collection.insert_one(new_user.__dict__)
        else:
            new_user = User.from_mongo(user)

        # Log in the user
        login_user(new_user)
        flash('Logged in successfully with Google.', 'success')
        return redirect(url_for('select_db'))
    except Exception as e:
        logger.error(f"Error during Google callback: {e}")
        flash('Failed to login with Google. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('google_token', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def generate_token(data, salt, expiration=3600):
    return serializer.dumps(data, salt=salt)

def verify_token(token, salt, expiration=3600):
    try:
        return serializer.loads(token, salt=salt, max_age=expiration)
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None

def send_email(subject, recipient, body):
    try:
        msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[recipient])
        msg.body = body
        mail.send(msg)
        logger.info(f"Email sent to {recipient}")
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        flash("Unable to send email. Please try again.", 'danger')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    new_password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8), 
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    security_question = SelectField('Security Question', 
                                    choices=[('pet', 'What was the name of your first pet?'), 
                                             ('mother_maiden', 'What is your mother\'s maiden name?'), 
                                             ('birth_city', 'In which city were you born?')],
                                    validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired()])
    submit = SubmitField('Register')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    security_question = SelectField('Security Question', 
                                    choices=[('pet', 'What was the name of your first pet?'), 
                                             ('school', 'What was the name of your elementary school?'), 
                                             ('city', 'In which city were you born?'), 
                                             ('friend', 'What is your best friend\'s first name?'), 
                                             ('mother', 'What is your mother\'s maiden name?')],
                                    validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(), 
        Length(min=8), 
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

def serialize_schema(schema):
    serialized_schema = {}
    for collection, details in schema.items():
        serialized_schema[collection] = {
            "total_documents": details["total_documents"],
            "avg_document_size": details["avg_document_size"],
            "fields": details["fields"],
            "nullable_fields": details.get("nullable_fields", []),
            "indexes": details.get("indexes", []),
        }
    return serialized_schema

def generate_schema(db):
    schema = {}
    db_details = {}
    try:
        if isinstance(db, dict):  # Assuming this is for JSON data
            schema = generate_json_schema(db)
            return schema, {}
        else:
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
                avg_document_size = next(collection.aggregate([
                    {"$group": {"_id": None, "avgSize": {"$avg": {"$bsonSize": "$$ROOT"}}}}
                ]), {}).get("avgSize", 0) / 1024

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
                    {"name": index_name, "fields": list(info["key"].items())}
                    for index_name, info in indexes.items()
                ]

                schema[collection_name] = {
                    "fields": list(sample_data.keys()),
                    "field_details": field_details,
                    "total_documents": total_documents,
                    "avg_document_size": avg_document_size,
                    "collection_size": db.command({"collStats": collection_name}).get("size", 0),
                    "indexes": index_info
                }

        logging.info("Schema generation successful.")
        return schema, db_details
    except Exception as e:
        logging.error(f"Error generating schema: {e}")
        return schema, db_details

def generate_json_schema(data):
    schema = {}
    for key, value in data.items():
        schema[key] = {
            "type": type(value).__name__
        }
    return schema

def generate_mongo_query(natural_language_query, schema):
    if not nlp_model:
        raise RuntimeError("NLP model is not available.")
    
    schema_context = json.dumps(schema, indent=2)
    prompt = f"Schema:\n{schema_context}\n\nQuery: {natural_language_query}\n\nMongoDB Query:"
    try:
        result = nlp_model(prompt, max_length=200, num_return_sequences=1)
        return json.loads(result[0]['generated_text'].strip())
    except json.JSONDecodeError:
        logger.error("Generated query is not valid JSON.")
        return None
    except Exception as e:
        logger.error(f"Error generating MongoDB query: {e}")

def execute_query_with_mongo_query(mongo_query):
    selected_db = session.get('selected_db')
    if not selected_db or selected_db['type'] != 'mongodb':
        return None, 'No MongoDB connection details in session or incorrect database type.'

    try:
        with MongoClient(selected_db['host'], selected_db['port']) as client:
            db = client[selected_db['database']]
            collection = db[mongo_query.get('collection')]
            
            if not collection:
                return None, 'Collection not found in the database.'
            
            query_filter = mongo_query.get('filter', {})
            projection = mongo_query.get('projection')
            limit = mongo_query.get('limit', 100)
            result = collection.find(query_filter, projection).limit(limit)
            
            return [
                {key: (str(value) if isinstance(value, (ObjectId, DBRef)) else value) for key, value in doc.items()}
                for doc in result
            ], None
    except Exception as e:
        logging.error(f"Error executing MongoDB query: {e}")
        return None, str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = user_collection.find_one({"email": email})
        if user and check_password_hash(user['password'], password):
            user_obj = User.from_mongo(user)
            login_user(user_obj)
            logger.info(f"User {email} logged in successfully.")
            flash('Login successful!', 'success')
            return redirect(url_for('select_db'))
        else:
            logger.warning(f"Failed login attempt for email: {email}")
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        if user_collection.find_one({"email": email}):
            flash('Email already registered.', 'danger')
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(form.new_password.data)
        new_user = {
            "email": email,
            "password": hashed_password,
            "security_question": form.security_question.data,
            "security_answer": generate_password_hash(form.security_answer.data)
        }
        user_collection.insert_one(new_user)
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = user_collection.find_one({"email": form.email.data})
        if user and user['security_question'] == form.security_question.data:
            if check_password_hash(user['security_answer'], form.security_answer.data):
                new_password_hash = generate_password_hash(form.new_password.data)
                user_collection.update_one({"email": form.email.data}, {"$set": {"password": new_password_hash}})
                flash('Password reset successful!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Incorrect security answer.', 'danger')
        else:
            flash('Email or security question not found.', 'danger')
    return render_template('reset_password.html', form=form)

@app.route('/select_db', methods=['GET', 'POST'])
@login_required
def select_db():
    if request.method == 'POST':
        db_type = request.form.get('db_type')
        if db_type == 'mongodb':
            session['selected_db'] = {
                'type': 'mongodb',
                'host': request.form.get('host', 'localhost'),
                'port': int(request.form.get('port', 27017)),
                'database': request.form.get('database')
            }
            return redirect(url_for('connect_database'))
        elif db_type == 'json':
            file = request.files['json_file']
            if file and file.filename.endswith('.json'):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                session['selected_db'] = {
                    'type': 'json',
                    'file_path': os.path.join(app.config['UPLOAD_FOLDER'], filename)
                }
                return redirect(url_for('connect_database'))
        flash('Invalid database selection or file type.', 'error')
    return render_template('select_db.html')

@app.route('/connect_database')
@login_required
def connect_database():
    if 'selected_db' not in session:
        flash('No database selected.', 'error')
        return redirect(url_for('select_db'))
    
    selected_db = session['selected_db']
    if selected_db['type'] == 'mongodb':
        try:
            with MongoClient(selected_db['host'], selected_db['port']) as client:
                db = client[selected_db['database']]
                schema, db_details = generate_schema(db)
                session['schema'] = schema
                return render_template('connect_database.html', schema=schema, db_details=db_details)
        except Exception as e:
            flash(f"Error connecting to MongoDB: {str(e)}", 'error')
            return redirect(url_for('select_db'))
    elif selected_db['type'] == 'json':
        try:
            with open(selected_db['file_path'], 'r') as f:
                data = json.load(f)
            schema, _ = generate_schema(data)
            session['schema'] = schema
            return render_template('connect_database.html', schema=schema)
        except Exception as e:
            flash(f"Error reading JSON file: {str(e)}", 'error')
            return redirect(url_for('select_db'))
    return redirect(url_for('select_db'))

@app.route('/nlp_query', methods=['POST'])
@login_required
def nlp_query():
    if 'selected_db' not in session:
        flash('No database selected.', 'error')
        return redirect(url_for('select_db'))
    
    query = request.form.get('query')
    if not query:
        flash('Query cannot be empty.', 'error')
        return redirect(url_for('select_db'))
    
    try:
        mongo_query = generate_mongo_query(query, session['schema'])
        if mongo_query:
            results, error = execute_query_with_mongo_query(mongo_query)
            if error:
                flash(error, 'error')
            else:
                return render_template('query_results.html', results=results, query=query)
        else:
            flash('Failed to generate MongoDB query from natural language.', 'error')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
    
    return redirect(url_for('select_db'))

if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
