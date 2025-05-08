import os
from flask import Flask, flash, redirect, url_for
# --- Added Import ---
from datetime import datetime, timezone
# --- End Import ---
# --- CORRECTED IMPORT BELOW ---
from .config import Config  # Use relative import because config.py is in the same package
# --- END CORRECTION ---
from .extensions import mongo, login_manager, csrf
from .models import User
from werkzeug.security import generate_password_hash
from pymongo.errors import ConnectionFailure, OperationFailure

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # --- Context Processor to Inject Year ---
    @app.context_processor
    def inject_current_year():
        """Injects the current year into all templates."""
        # Use timezone.utc to ensure consistency regardless of server timezone
        from pytz import timezone
        india_timezone = timezone('Asia/Kolkata')
        return {'current_year': datetime.now(india_timezone).year}
    # --- End Context Processor ---


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
    # This block runs when the app context is available, usually during startup or requests
    with app.app_context():
        try:
            # The ismaster command is cheap and does not require auth. Used to check basic connectivity.
            print("--- [__init__.py] Attempting MongoDB connection check...")
            mongo.cx.admin.command('ismaster')
            print("--- [__init__.py] MongoDB connection successful.")

            # Check if the database exists (or is accessible) by listing databases
            db_list = mongo.cx.list_database_names()
            db_name = app.config['MONGO_DB_NAME']
            print(f"--- [__init__.py] Checking for database: {db_name}")
            print(f"--- [__init__.py] Accessible databases: {db_list}")

            if db_name not in db_list:
                 print(f"--- [__init__.py] Database '{db_name}' not found in list. It might be created on first write.")
                 # MongoDB creates DB on first write, but we can try creating a collection
                 # to ensure it exists and check permissions early.
                 try:
                     # Use a temporary collection name
                     temp_collection_name = "_db_creation_check"
                     mongo.db[temp_collection_name].insert_one({'_check_creation': True})
                     print(f"--- [__init__.py] Successfully wrote to temp collection in '{db_name}'.")
                     mongo.db[temp_collection_name].delete_one({'_check_creation': True})
                     print(f"--- [__init__.py] Successfully deleted from temp collection in '{db_name}'. Database access confirmed.")
                     # Optionally drop the temp collection entirely if desired
                     # mongo.db.drop_collection(temp_collection_name)
                 except OperationFailure as e:
                     print(f"--- [__init__.py] ERROR: Could not write to database '{db_name}'. Check permissions. Error: {e}")
                     # Decide how to handle this - exit, warn, etc.
                     # For now, we continue and rely on later checks.


            # Setup first admin user if no users exist in the 'users' collection
            users_collection = mongo.db.users # Explicitly reference the collection
            print(f"--- [__init__.py] Checking user count in collection: {users_collection.name}")
            user_count = users_collection.count_documents({})
            print(f"--- [__init__.py] Found {user_count} user(s).")

            if user_count == 0:
                print("--- [__init__.py] No users found. Creating initial admin user...")
                admin_username = app.config['ADMIN_USERNAME']
                admin_password = app.config['ADMIN_PASSWORD']
                hashed_password = generate_password_hash(admin_password)
                print(f"--- [__init__.py] Hashing password for admin: {admin_username}")
                try:
                    insert_result = users_collection.insert_one({
                        'username': admin_username,
                        'password_hash': hashed_password,
                        'is_admin': True,
                        'is_temp_admin': False,
                        'temp_admin_expiry': None
                    })
                    print(f"--- [__init__.py] Admin user '{admin_username}' created successfully with ID: {insert_result.inserted_id}.")
                    print(f"--- [__init__.py] IMPORTANT: Log in as '{admin_username}' with the password set in your .env file and change it immediately.")
                except Exception as e:
                    print(f"--- [__init__.py] ERROR: Could not create initial admin user: {e}")

        except ConnectionFailure as e:
            print(f"--- [__init__.py] ERROR: Could not connect to MongoDB at {app.config.get('MONGO_HOST', 'N/A')}:{app.config.get('MONGO_PORT', 'N/A')}. Please check configuration and ensure MongoDB is running.")
            print(f"--- [__init__.py] Error details: {e}")
            # Optionally, exit the application if DB connection is critical at startup
            # import sys
            # sys.exit(1)
        except OperationFailure as e:
             # This might catch authentication errors if authSource is wrong or creds are bad
             print(f"--- [__init__.py] ERROR: MongoDB operation failed during startup check. Check authentication credentials (user/pass/authSource) and database permissions.")
             print(f"--- [__init__.py] Error details: {e}")
             # Optionally, exit
             # import sys
             # sys.exit(1)
        except Exception as e:
             # Catch any other unexpected errors during startup checks
             print(f"--- [__init__.py] ERROR: An unexpected error occurred during app initialization: {e}")
             import traceback
             traceback.print_exc() # Print full traceback for debugging


    # Register blueprints
    # Import them *after* app and extensions are initialized to avoid circular imports
    print("--- [__init__.py] Registering blueprints...")
    from .routes.auth import auth_bp
    from .routes.main import main_bp
    from .routes.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    print("--- [__init__.py] Blueprints registered.")

    # Optional: Add a simple root redirect to the main index or login
    @app.route('/')
    def root_redirect():
        # Redirect to login or dashboard depending on preference
        # return redirect(url_for('auth.login'))
        return redirect(url_for('main.index')) # Assuming main.index handles auth check/redirect

    print("--- [__init__.py] create_app function finished.")
    return app