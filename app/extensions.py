from flask_pymongo import PyMongo
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

mongo = PyMongo()
login_manager = LoginManager()
csrf = CSRFProtect()