from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from .extensions import mongo
from .utils import encrypt_string, decrypt_string
from datetime import datetime, timezone

# --- User Model ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data.get('_id'))
        self.username = user_data.get('username')
        self.password_hash = user_data.get('password_hash')
        self.is_admin = user_data.get('is_admin', False)
        self.is_temp_admin = user_data.get('is_temp_admin', False)
        self.temp_admin_expiry = user_data.get('temp_admin_expiry') # Store as UTC datetime

    @staticmethod
    def get_by_username(username):
        user_data = mongo.db.users.find_one({'username': username})
        return User(user_data) if user_data else None

    @staticmethod
    def get_by_id(user_id):
        try:
            user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            return User(user_data) if user_data else None
        except Exception: # Handle invalid ObjectId format
            return None

    @staticmethod
    def get_all_users():
        users_data = mongo.db.users.find({}, {'password_hash': 0}) # Exclude password hash
        return [User(user_data) for user_data in users_data]

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {'$set': {'password_hash': self.password_hash}})

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def grant_temp_admin(self, expiry_datetime_utc=None):
        update_fields = {'is_temp_admin': True}
        if expiry_datetime_utc:
            update_fields['temp_admin_expiry'] = expiry_datetime_utc
        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {'$set': update_fields})
        self.is_temp_admin = True
        self.temp_admin_expiry = expiry_datetime_utc

    def revoke_temp_admin(self):
        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {'$set': {'is_temp_admin': False, 'temp_admin_expiry': None}})
        self.is_temp_admin = False
        self.temp_admin_expiry = None

    def is_admin_or_temp(self):
        self.check_and_revoke_temp_admin() # Check expiry before returning status
        return self.is_admin or self.is_temp_admin

    def check_and_revoke_temp_admin(self):
        """Checks if temp admin has expired and revokes if necessary."""
        if self.is_temp_admin and self.temp_admin_expiry:
            # Ensure comparison is between timezone-aware datetimes (UTC)
            if isinstance(self.temp_admin_expiry, datetime) and self.temp_admin_expiry.tzinfo is None:
                 # If expiry was stored naive, assume UTC (or handle based on app's convention)
                 expiry_aware = self.temp_admin_expiry.replace(tzinfo=timezone.utc)
            else:
                 expiry_aware = self.temp_admin_expiry

            now_aware = datetime.now(timezone.utc)

            if now_aware > expiry_aware:
                self.revoke_temp_admin()


# --- Vault Item Models ---
# These are not classes in the same way as User, but functions interacting with collections

# -- Servers --
def add_server(server_name, ip_address, login_as, password, notes, created_by_id):
    encrypted_password = encrypt_string(password)
    if not encrypted_password: return False # Encryption failed
    server_data = {
        'server_name': server_name,
        'ip_address': ip_address,
        'login_as': login_as,
        'encrypted_password': encrypted_password,
        'notes': notes,
        'created_by': ObjectId(created_by_id),
        'last_updated': datetime.now(timezone.utc)
    }
    result = mongo.db.servers.insert_one(server_data)
    return result.inserted_id

def get_all_servers():
    servers_cursor = mongo.db.servers.find()
    servers = []
    for server in servers_cursor:
        server['_id'] = str(server['_id']) # Convert ObjectId for easier use
        # Decrypt password ONLY when needed (e.g., view/copy), not in the list view
        # server['password'] = decrypt_string(server['encrypted_password']) # Example - DO NOT DO THIS HERE
        servers.append(server)
    return servers

def get_server_by_id(server_id):
    try:
        server = mongo.db.servers.find_one({'_id': ObjectId(server_id)})
        if server:
            server['_id'] = str(server['_id'])
            # Decrypt password for editing or viewing details
            # Careful: only decrypt when absolutely necessary
            # server['password'] = decrypt_string(server['encrypted_password'])
        return server
    except Exception:
        return None

def update_server(server_id, update_data):
    # Re-encrypt password if it's being changed
    if 'password' in update_data and update_data['password']:
        encrypted_password = encrypt_string(update_data['password'])
        if not encrypted_password: return False # Encryption failed
        update_data['encrypted_password'] = encrypted_password
        del update_data['password'] # Don't store the plain text password
    else:
        # Ensure password isn't accidentally removed if not provided
        update_data.pop('password', None)
        update_data.pop('encrypted_password', None) # Don't allow direct setting of encrypted

    update_data['last_updated'] = datetime.now(timezone.utc)
    result = mongo.db.servers.update_one(
        {'_id': ObjectId(server_id)},
        {'$set': update_data}
    )
    return result.modified_count > 0

def delete_server(server_id):
    result = mongo.db.servers.delete_one({'_id': ObjectId(server_id)})
    return result.deleted_count > 0


# -- Laptops --
def add_laptop(laptop_id_str, employee_name, username, password, installed_software, notes, created_by_id):
    encrypted_password = encrypt_string(password)
    if not encrypted_password: return False
    laptop_data = {
        'laptop_id': laptop_id_str,
        'employee_name': employee_name,
        'username': username,
        'encrypted_password': encrypted_password,
        'installed_software': installed_software, # Store as list of strings
        'notes': notes,
        'created_by': ObjectId(created_by_id),
        'last_updated': datetime.now(timezone.utc)
    }
    result = mongo.db.laptops.insert_one(laptop_data)
    return result.inserted_id

def get_all_laptops():
    laptops_cursor = mongo.db.laptops.find()
    laptops = []
    for laptop in laptops_cursor:
        laptop['_id'] = str(laptop['_id'])
        laptops.append(laptop)
    return laptops

def get_laptop_by_id(laptop_mongo_id): # Use Mongo's _id
    try:
        laptop = mongo.db.laptops.find_one({'_id': ObjectId(laptop_mongo_id)})
        if laptop:
            laptop['_id'] = str(laptop['_id'])
        return laptop
    except Exception:
        return None

def update_laptop(laptop_mongo_id, update_data):
    if 'password' in update_data and update_data['password']:
        encrypted_password = encrypt_string(update_data['password'])
        if not encrypted_password: return False
        update_data['encrypted_password'] = encrypted_password
        del update_data['password']
    else:
        update_data.pop('password', None)
        update_data.pop('encrypted_password', None)

    # Ensure installed_software is handled correctly (e.g., split string if needed)
    if 'installed_software' in update_data and isinstance(update_data['installed_software'], str):
        update_data['installed_software'] = [s.strip() for s in update_data['installed_software'].split(',') if s.strip()]


    update_data['last_updated'] = datetime.now(timezone.utc)
    result = mongo.db.laptops.update_one(
        {'_id': ObjectId(laptop_mongo_id)},
        {'$set': update_data}
    )
    return result.modified_count > 0

def delete_laptop(laptop_mongo_id):
    result = mongo.db.laptops.delete_one({'_id': ObjectId(laptop_mongo_id)})
    return result.deleted_count > 0

# -- Personal Passwords --
def add_personal_password(user_id, website, username, password, notes):
    encrypted_password = encrypt_string(password)
    if not encrypted_password: return False
    personal_data = {
        'user_id': ObjectId(user_id),
        'website_or_service': website,
        'username': username,
        'encrypted_password': encrypted_password,
        'notes': notes,
        'last_updated': datetime.now(timezone.utc)
    }
    result = mongo.db.personal_passwords.insert_one(personal_data)
    return result.inserted_id

def get_personal_passwords_for_user(user_id):
    passwords_cursor = mongo.db.personal_passwords.find({'user_id': ObjectId(user_id)})
    passwords = []
    for pw in passwords_cursor:
        pw['_id'] = str(pw['_id'])
        passwords.append(pw)
    return passwords

def get_personal_password_by_id(password_id, user_id):
    try:
        pw = mongo.db.personal_passwords.find_one({
            '_id': ObjectId(password_id),
            'user_id': ObjectId(user_id) # Ensure user owns this password
        })
        if pw:
            pw['_id'] = str(pw['_id'])
        return pw
    except Exception:
        return None

def update_personal_password(password_id, user_id, update_data):
     # Ensure user owns this password before updating
    current_pw = get_personal_password_by_id(password_id, user_id)
    if not current_pw:
        return False # Item not found or doesn't belong to user

    if 'password' in update_data and update_data['password']:
        encrypted_password = encrypt_string(update_data['password'])
        if not encrypted_password: return False
        update_data['encrypted_password'] = encrypted_password
        del update_data['password']
    else:
        update_data.pop('password', None)
        update_data.pop('encrypted_password', None)

    update_data['last_updated'] = datetime.now(timezone.utc)
    result = mongo.db.personal_passwords.update_one(
        {'_id': ObjectId(password_id), 'user_id': ObjectId(user_id)}, # Double check ownership
        {'$set': update_data}
    )
    return result.modified_count > 0

def delete_personal_password(password_id, user_id):
     # Ensure user owns this password before deleting
    result = mongo.db.personal_passwords.delete_one({
        '_id': ObjectId(password_id),
        'user_id': ObjectId(user_id)
    })
    return result.deleted_count > 0

def get_decrypted_password(item_type: str, item_id: str, user_id: str = None) -> str | None:
    """Safely retrieves and decrypts a password for a specific item."""
    item = None
    encrypted_pw = None
    try:
        if item_type == 'server':
            item = mongo.db.servers.find_one({'_id': ObjectId(item_id)})
        elif item_type == 'laptop':
            item = mongo.db.laptops.find_one({'_id': ObjectId(item_id)})
        elif item_type == 'personal':
            if not user_id: return None # User ID required for personal
            item = mongo.db.personal_passwords.find_one({'_id': ObjectId(item_id), 'user_id': ObjectId(user_id)})
        else:
            return None # Invalid type

        if item:
            encrypted_pw = item.get('encrypted_password')
            if encrypted_pw:
                return decrypt_string(encrypted_pw)

    except Exception as e:
        print(f"Error getting/decrypting password for {item_type} {item_id}: {e}")

    return None