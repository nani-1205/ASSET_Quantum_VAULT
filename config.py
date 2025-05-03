import os
from dotenv import load_dotenv

# Load environment variables from .env file
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '../.env')) # Adjust path if needed

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    MONGO_USERNAME = os.environ.get('MONGO_USERNAME')
    MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD')
    MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
    MONGO_PORT = int(os.environ.get('MONGO_PORT', 27017))
    MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME', 'asset_quantum_vault')
    MONGO_AUTH_DB = os.environ.get('MONGO_AUTH_DB', 'admin')
    MONGO_URI = f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB_NAME}?authSource={MONGO_AUTH_DB}"

    # Encryption Key - Load securely!
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    if not ENCRYPTION_KEY:
        raise ValueError("No ENCRYPTION_KEY set for Flask application. Please set it in .env or environment variables.")
    ENCRYPTION_KEY_BYTES = ENCRYPTION_KEY.encode() # Fernet needs bytes

    # Initial Admin Credentials (used only if DB is empty)
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme') # Change this default

    # Flask-WTF CSRF Protection
    WTF_CSRF_ENABLED = True

    # Optional: Configure session cookie settings for production
    # SESSION_COOKIE_SECURE = True
    # SESSION_COOKIE_HTTPONLY = True
    # SESSION_COOKIE_SAMESITE = 'Lax'

# You could add DevelopmentConfig, ProductionConfig, TestingConfig subclasses here
# if needed, inheriting from Config and overriding specific settings.