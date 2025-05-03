import os
from flask import Flask, flash, redirect, url_for
from config import Config
from .extensions import mongo, login_manager, csrf
from .models import User
from werkzeug.security import generate_password_hash
from pymongo.errors import ConnectionFailure, OperationFailure

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions
    mongo.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app) # Initialize CSRF protection

    # Configure Flask-Login
    login_manager.login_view = 'auth.login' # The route for the login page
    login_manager.login_message_category = 'info'
    login_manager.login_message = "Please log in to access this page."

    @login_manager.user_loader
    def load_user(user_id):
        # Flask-Login callback to load a user from the session
        return User.get_by_id(user_id)

    # Check DB connection and create initial admin if necessary
    with app.app_context():
        try:
            # The ismaster command is cheap and does not require auth.
            mongo.cx.admin.command('ismaster')
            print("MongoDB connection successful.")

            # Check if the database exists (or is accessible)
            db_list = mongo.cx.list_database_names()
            db_name = app.config['MONGO_DB_NAME']

            if db_name not in db_list:
                 print(f"Database '{db_name}' not found. It might be created on first write.")
                 # MongoDB creates DB on first write, but we can try creating a collection
                 # to ensure it exists and check permissions early.
                 try:
                     mongo.db.users.insert_one({'_check_creation': True})
                     mongo.db.users.delete_one({'_check_creation': True})
                     print(f"Successfully accessed/created database '{db_name}'.")
                 except OperationFailure as e:
                     print(f"ERROR: Could not write to database '{db_name}'. Check permissions. Error: {e}")
                     # Decide how to handle this - exit, warn, etc.
                     # For now, we continue and rely on later checks.


            # Setup first admin user if no users exist
            if mongo.db.users.count_documents({}) == 0:
                print("No users found. Creating initial admin user...")
                admin_username = app.config['ADMIN_USERNAME']
                admin_password = app.config['ADMIN_PASSWORD']
                hashed_password = generate_password_hash(admin_password)
                try:
                    mongo.db.users.insert_one({
                        'username': admin_username,
                        'password_hash': hashed_password,
                        'is_admin': True,
                        'is_temp_admin': False,
                        'temp_admin_expiry': None
                    })
                    print(f"Admin user '{admin_username}' created successfully.")
                    print(f"IMPORTANT: Log in as '{admin_username}' with the password set in your .env file and change it immediately.")
                except Exception as e:
                    print(f"ERROR: Could not create initial admin user: {e}")

        except ConnectionFailure as e:
            print(f"ERROR: Could not connect to MongoDB at {app.config['MONGO_HOST']}:{app.config['MONGO_PORT']}. Please check configuration and ensure MongoDB is running.")
            print(f"Error details: {e}")
            # Optionally, exit the application if DB connection is critical at startup
            # import sys
            # sys.exit(1)
        except OperationFailure as e:
             # This might catch authentication errors if authSource is wrong or creds are bad
             print(f"ERROR: MongoDB operation failed. Check authentication credentials and database permissions.")
             print(f"Error details: {e}")
             # Optionally, exit
             # import sys
             # sys.exit(1)


    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.main import main_bp
    from .routes.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Optional: Add a simple root redirect to the main index or login
    @app.route('/')
    def root_redirect():
        return redirect(url_for('main.index'))

    return app