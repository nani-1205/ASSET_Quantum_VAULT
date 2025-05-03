import os
from dotenv import load_dotenv

# Get the absolute path of the directory the config.py file is in (app directory)
basedir = os.path.abspath(os.path.dirname(__file__))
print(f"--- [config.py] Config file directory (basedir): {basedir}")

# Construct the path to the .env file, assuming it's one level up from the 'app' directory
# Use abspath AFTER joining to resolve '..' correctly relative to basedir
dotenv_path = os.path.abspath(os.path.join(basedir, '../.env'))

# --- Debug: Print the final path being checked for .env ---
print(f"--- [config.py] Attempting to load .env file from (final path): {dotenv_path}")

# Load environment variables from the specified .env file path
# verbose=True will print debugging information from python-dotenv itself
loaded = load_dotenv(dotenv_path=dotenv_path, verbose=True)

# --- Debug: Print whether dotenv reported successful loading ---
if loaded:
    print(f"--- [config.py] python-dotenv reported successfully loading '{dotenv_path}'.")
else:
    print(f"--- [config.py] WARNING: python-dotenv reported that it did NOT load '{dotenv_path}'. Check permissions and path.")
    if not os.path.exists(dotenv_path):
        print(f"--- [config.py] CRITICAL: The file '{dotenv_path}' does not exist.")
    else:
         print(f"--- [config.py] INFO: File '{dotenv_path}' exists, but was not loaded. Check read permissions.")


class Config:
    """Base configuration."""
    # --- Debug: Retrieve SECRET_KEY and print its value ---
    SECRET_KEY = os.environ.get('SECRET_KEY')
    print(f"--- [config.py] SECRET_KEY from env: {'*' * len(SECRET_KEY) if SECRET_KEY else 'Not Found'}") # Avoid logging the actual key
    if not SECRET_KEY:
        print("--- [config.py] WARNING: SECRET_KEY not found in environment.")
    # Provide a default only as a last resort for basic running, but it's insecure
    SECRET_KEY = SECRET_KEY or 'default-insecure-key-set-in-env'

    MONGO_USERNAME = os.environ.get('MONGO_USERNAME')
    MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD')
    MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
    MONGO_PORT = int(os.environ.get('MONGO_PORT', 27017))
    MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME', 'asset_quantum_vault')
    MONGO_AUTH_DB = os.environ.get('MONGO_AUTH_DB', 'admin')
    MONGO_URI = f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB_NAME}?authSource={MONGO_AUTH_DB}"

    # --- Debug: Retrieve ENCRYPTION_KEY and print its value before checking ---
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    print(f"--- [config.py] ENCRYPTION_KEY from env: {'*' * len(ENCRYPTION_KEY) if ENCRYPTION_KEY else 'Not Found'}") # Avoid logging the actual key

    # Check if ENCRYPTION_KEY was successfully loaded
    if not ENCRYPTION_KEY:
        print("--- [config.py] CRITICAL: ENCRYPTION_KEY not found in environment variables after attempting to load .env.")
        raise ValueError("No ENCRYPTION_KEY set for Flask application. Please check .env file path, permissions, and content.")

    # Ensure the key is bytes for Fernet
    try:
        ENCRYPTION_KEY_BYTES = ENCRYPTION_KEY.encode('utf-8')
        print(f"--- [config.py] ENCRYPTION_KEY successfully encoded to bytes.")
    except Exception as e:
         print(f"--- [config.py] CRITICAL: Failed to encode ENCRYPTION_KEY to bytes: {e}")
         raise ValueError(f"Invalid ENCRYPTION_KEY format: {e}")


    # Initial Admin Credentials (used only if DB is empty)
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme') # Change this default
    # --- Debug: Print admin username being used ---
    print(f"--- [config.py] Initial ADMIN_USERNAME: {ADMIN_USERNAME}")


    # Flask-WTF CSRF Protection
    WTF_CSRF_ENABLED = True

    # Optional: Configure session cookie settings for production
    # SESSION_COOKIE_SECURE = True
    # SESSION_COOKIE_HTTPONLY = True
    # SESSION_COOKIE_SAMESITE = 'Lax'

# You could add DevelopmentConfig, ProductionConfig, TestingConfig subclasses here
# if needed, inheriting from Config and overriding specific settings.