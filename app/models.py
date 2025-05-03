from bson import ObjectId, InvalidId # Make sure InvalidId is imported
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
# --- Added Import ---
from typing import Optional, List, Dict, Any # Import Optional and other useful types
# --- End Import ---
from .extensions import mongo
from .utils import encrypt_string, decrypt_string # Assuming decrypt_string now returns Optional[str]
from datetime import datetime, timezone

# --- User Model ---
class User(UserMixin):
    def __init__(self, user_data: Dict[str, Any]): # Added type hint for input
        self.id: str = str(user_data.get('_id'))
        self.username: Optional[str] = user_data.get('username')
        self.password_hash: Optional[str] = user_data.get('password_hash')
        self.is_admin: bool = user_data.get('is_admin', False)
        self.is_temp_admin: bool = user_data.get('is_temp_admin', False)
        self.temp_admin_expiry: Optional[datetime] = user_data.get('temp_admin_expiry') # Store as UTC datetime

    @staticmethod
    def get_by_username(username: str) -> Optional['User']: # Return type hint includes forward ref
        user_data = mongo.db.users.find_one({'username': username})
        return User(user_data) if user_data else None

    @staticmethod
    def get_by_id(user_id: str) -> Optional['User']: # Return type hint
        try:
            # Ensure user_id is a valid ObjectId string before conversion
            if not ObjectId.is_valid(user_id):
                 return None
            user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            return User(user_data) if user_data else None
        except Exception as e: # Handle invalid ObjectId format or other errors
            print(f"--- [models.py] Error in get_by_id for ID {user_id}: {e}")
            return None

    @staticmethod
    def get_all_users() -> List['User']: # Return type hint
        users_data = mongo.db.users.find({}, {'password_hash': 0}) # Exclude password hash
        return [User(user_data) for user_data in users_data]

    def set_password(self, password: str) -> None: # Return type hint
        self.password_hash = generate_password_hash(password)
        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {'$set': {'password_hash': self.password_hash}})

    def check_password(self, password: str) -> bool: # Return type hint
        if not self.password_hash: # Handle case where user might not have a password hash set yet
             return False
        return check_password_hash(self.password_hash, password)

    def grant_temp_admin(self, expiry_datetime_utc: Optional[datetime] = None) -> None: # Return type hint
        update_fields = {'is_temp_admin': True}
        if expiry_datetime_utc:
            update_fields['temp_admin_expiry'] = expiry_datetime_utc
        else: # Ensure expiry is explicitly null if not provided
             update_fields['temp_admin_expiry'] = None

        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {'$set': update_fields})
        self.is_temp_admin = True
        self.temp_admin_expiry = expiry_datetime_utc

    def revoke_temp_admin(self) -> None: # Return type hint
        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {'$set': {'is_temp_admin': False, 'temp_admin_expiry': None}})
        self.is_temp_admin = False
        self.temp_admin_expiry = None

    def is_admin_or_temp(self) -> bool: # Return type hint
        self.check_and_revoke_temp_admin() # Check expiry before returning status
        return self.is_admin or self.is_temp_admin

    def check_and_revoke_temp_admin(self) -> None: # Return type hint
        """Checks if temp admin has expired and revokes if necessary."""
        if self.is_temp_admin and self.temp_admin_expiry:
            # Ensure comparison is between timezone-aware datetimes (UTC)
            if isinstance(self.temp_admin_expiry, datetime):
                 # Make expiry aware if it's naive (assume UTC)
                 expiry_aware = self.temp_admin_expiry.replace(tzinfo=timezone.utc) if self.temp_admin_expiry.tzinfo is None else self.temp_admin_expiry
                 now_aware = datetime.now(timezone.utc)
                 if now_aware > expiry_aware:
                    print(f"--- [models.py] Temp admin expired for user {self.username}. Revoking.")
                    self.revoke_temp_admin()
            else:
                 # Log if expiry is not a datetime object unexpectedly
                 print(f"--- [models.py] Warning: temp_admin_expiry for user {self.username} is not a datetime object: {type(self.temp_admin_expiry)}")


# --- Vault Item Models ---
# These are not classes in the same way as User, but functions interacting with collections

# Helper type for vault items returned from DB
VaultItem = Dict[str, Any]

# -- Servers --
def add_server(server_name: str, ip_address: Optional[str], login_as: str, password: str, notes: Optional[str], created_by_id: str) -> Optional[ObjectId]:
    encrypted_password = encrypt_string(password)
    if not encrypted_password:
        print("--- [models.py] ERROR: Failed to encrypt server password.")
        return None # Encryption failed
    server_data = {
        'server_name': server_name,
        'ip_address': ip_address,
        'login_as': login_as,
        'encrypted_password': encrypted_password,
        'notes': notes,
        'created_by': ObjectId(created_by_id),
        'last_updated': datetime.now(timezone.utc)
    }
    try:
        result = mongo.db.servers.insert_one(server_data)
        return result.inserted_id
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to add server: {e}")
        return None

def get_all_servers() -> List[VaultItem]:
    servers: List[VaultItem] = []
    try:
        servers_cursor = mongo.db.servers.find()
        for server in servers_cursor:
            server['_id'] = str(server['_id']) # Convert ObjectId for easier use
            server['created_by'] = str(server.get('created_by')) # Convert creator ID too
            # Decrypt password ONLY when needed (e.g., view/copy), not in the list view
            servers.append(server)
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to get all servers: {e}")
    return servers

def get_server_by_id(server_id: str) -> Optional[VaultItem]: # Changed return type hint
    try:
        if not ObjectId.is_valid(server_id): return None
        server = mongo.db.servers.find_one({'_id': ObjectId(server_id)})
        if server:
            server['_id'] = str(server['_id'])
            server['created_by'] = str(server.get('created_by'))
        return server
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to get server by ID {server_id}: {e}")
        return None

def update_server(server_id: str, update_data: Dict[str, Any]) -> bool:
    # Re-encrypt password if it's being changed
    if 'password' in update_data and update_data['password']:
        encrypted_password = encrypt_string(update_data['password'])
        if not encrypted_password:
            print("--- [models.py] ERROR: Failed to encrypt server password during update.")
            return False # Encryption failed
        update_data['encrypted_password'] = encrypted_password
        del update_data['password'] # Don't store the plain text password
    else:
        # Ensure password isn't accidentally removed if not provided
        update_data.pop('password', None) # Remove plain text if present
        # We keep the existing encrypted password if not updating

    update_data['last_updated'] = datetime.now(timezone.utc)
    # Remove fields that shouldn't be directly updated via $set if they sneak in
    update_data.pop('_id', None)
    update_data.pop('created_by', None)

    try:
        if not ObjectId.is_valid(server_id): return False
        result = mongo.db.servers.update_one(
            {'_id': ObjectId(server_id)},
            {'$set': update_data}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to update server ID {server_id}: {e}")
        return False

def delete_server(server_id: str) -> bool:
    try:
        if not ObjectId.is_valid(server_id): return False
        result = mongo.db.servers.delete_one({'_id': ObjectId(server_id)})
        return result.deleted_count > 0
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to delete server ID {server_id}: {e}")
        return False

# -- Laptops --
def add_laptop(laptop_id_str: str, employee_name: str, username: str, password: str, installed_software: List[str], notes: Optional[str], created_by_id: str) -> Optional[ObjectId]:
    encrypted_password = encrypt_string(password)
    if not encrypted_password:
        print("--- [models.py] ERROR: Failed to encrypt laptop password.")
        return None
    laptop_data = {
        'laptop_id': laptop_id_str, # This is the asset tag, not Mongo _id
        'employee_name': employee_name,
        'username': username,
        'encrypted_password': encrypted_password,
        'installed_software': installed_software, # Store as list of strings
        'notes': notes,
        'created_by': ObjectId(created_by_id),
        'last_updated': datetime.now(timezone.utc)
    }
    try:
        result = mongo.db.laptops.insert_one(laptop_data)
        return result.inserted_id
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to add laptop: {e}")
        return None

def get_all_laptops() -> List[VaultItem]:
    laptops: List[VaultItem] = []
    try:
        laptops_cursor = mongo.db.laptops.find()
        for laptop in laptops_cursor:
            laptop['_id'] = str(laptop['_id'])
            laptop['created_by'] = str(laptop.get('created_by'))
            laptops.append(laptop)
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to get all laptops: {e}")
    return laptops

def get_laptop_by_id(laptop_mongo_id: str) -> Optional[VaultItem]:
    try:
        if not ObjectId.is_valid(laptop_mongo_id): return None
        laptop = mongo.db.laptops.find_one({'_id': ObjectId(laptop_mongo_id)})
        if laptop:
            laptop['_id'] = str(laptop['_id'])
            laptop['created_by'] = str(laptop.get('created_by'))
        return laptop
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to get laptop by ID {laptop_mongo_id}: {e}")
        return None

# --- NEW FUNCTION ---
def get_laptops_by_ids(laptop_ids: List[str]) -> List[VaultItem]:
    """Fetches laptop data for a specific list of MongoDB _ids."""
    laptops: List[VaultItem] = []
    if not laptop_ids:
        return laptops # Return empty list if no IDs provided

    object_ids = []
    # Convert string IDs to ObjectIds, filtering out invalid ones
    for laptop_id in laptop_ids:
        if ObjectId.is_valid(laptop_id):
            object_ids.append(ObjectId(laptop_id))
        else:
            print(f"--- [models.py] Warning: Invalid laptop ID format skipped: {laptop_id}")

    if not object_ids:
        return laptops # Return empty list if no valid IDs remain

    try:
        # Use the $in operator to find documents matching any ID in the list
        laptops_cursor = mongo.db.laptops.find({'_id': {'$in': object_ids}})
        for laptop in laptops_cursor:
            laptop['_id'] = str(laptop['_id'])
            laptop['created_by'] = str(laptop.get('created_by'))
            laptops.append(laptop)
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to get laptops by IDs: {e}")
    return laptops
# --- END NEW FUNCTION ---

def update_laptop(laptop_mongo_id: str, update_data: Dict[str, Any]) -> bool:
    if 'password' in update_data and update_data['password']:
        encrypted_password = encrypt_string(update_data['password'])
        if not encrypted_password:
            print("--- [models.py] ERROR: Failed to encrypt laptop password during update.")
            return False
        update_data['encrypted_password'] = encrypted_password
        del update_data['password']
    else:
        update_data.pop('password', None)

    # Ensure installed_software is handled correctly (expecting list from route now)
    if 'installed_software' in update_data:
        if isinstance(update_data['installed_software'], str):
            # If it's still a string, split it (fallback)
            update_data['installed_software'] = [s.strip() for s in update_data['installed_software'].split(',') if s.strip()]
        elif not isinstance(update_data['installed_software'], list):
             # If it's neither string nor list, handle appropriately (e.g., clear or log error)
             print(f"--- [models.py] Warning: Invalid type for installed_software during update: {type(update_data['installed_software'])}. Setting to empty list.")
             update_data['installed_software'] = []
    # If 'installed_software' is not in update_data, it remains unchanged

    update_data['last_updated'] = datetime.now(timezone.utc)
    update_data.pop('_id', None)
    update_data.pop('created_by', None)

    try:
        if not ObjectId.is_valid(laptop_mongo_id): return False
        result = mongo.db.laptops.update_one(
            {'_id': ObjectId(laptop_mongo_id)},
            {'$set': update_data}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to update laptop ID {laptop_mongo_id}: {e}")
        return False

def delete_laptop(laptop_mongo_id: str) -> bool:
    try:
        if not ObjectId.is_valid(laptop_mongo_id): return False
        result = mongo.db.laptops.delete_one({'_id': ObjectId(laptop_mongo_id)})
        return result.deleted_count > 0
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to delete laptop ID {laptop_mongo_id}: {e}")
        return False

# -- Personal Passwords --
def add_personal_password(user_id: str, website: str, username: str, password: str, notes: Optional[str]) -> Optional[ObjectId]:
    if not ObjectId.is_valid(user_id):
         print(f"--- [models.py] ERROR: Invalid user_id format '{user_id}' in add_personal_password.")
         return None
    encrypted_password = encrypt_string(password)
    if not encrypted_password:
        print("--- [models.py] ERROR: Failed to encrypt personal password.")
        return None
    personal_data = {
        'user_id': ObjectId(user_id), # Ensure user_id is valid ObjectId before calling this
        'website_or_service': website,
        'username': username,
        'encrypted_password': encrypted_password,
        'notes': notes,
        'last_updated': datetime.now(timezone.utc)
    }
    try:
        result = mongo.db.personal_passwords.insert_one(personal_data)
        return result.inserted_id
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to add personal password for user {user_id}: {e}")
        return None

def get_personal_passwords_for_user(user_id: str) -> List[VaultItem]:
    passwords: List[VaultItem] = []
    try:
        if not ObjectId.is_valid(user_id): return []
        passwords_cursor = mongo.db.personal_passwords.find({'user_id': ObjectId(user_id)})
        for pw in passwords_cursor:
            pw['_id'] = str(pw['_id'])
            pw['user_id'] = str(pw.get('user_id'))
            passwords.append(pw)
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to get personal passwords for user {user_id}: {e}")
    return passwords

def get_personal_password_by_id(password_id: str, user_id: str) -> Optional[VaultItem]:
    try:
        if not ObjectId.is_valid(password_id) or not ObjectId.is_valid(user_id): return None
        pw = mongo.db.personal_passwords.find_one({
            '_id': ObjectId(password_id),
            'user_id': ObjectId(user_id) # Ensure user owns this password
        })
        if pw:
            pw['_id'] = str(pw['_id'])
            pw['user_id'] = str(pw.get('user_id'))
        return pw
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to get personal password ID {password_id} for user {user_id}: {e}")
        return None

def update_personal_password(password_id: str, user_id: str, update_data: Dict[str, Any]) -> bool:
     # Ensure user owns this password before updating
     # We don't need get_personal_password_by_id here, the update query checks ownership
    if not ObjectId.is_valid(password_id) or not ObjectId.is_valid(user_id): return False

    if 'password' in update_data and update_data['password']:
        encrypted_password = encrypt_string(update_data['password'])
        if not encrypted_password:
            print("--- [models.py] ERROR: Failed to encrypt personal password during update.")
            return False
        update_data['encrypted_password'] = encrypted_password
        del update_data['password']
    else:
        update_data.pop('password', None)

    update_data['last_updated'] = datetime.now(timezone.utc)
    # Don't allow changing ownership or mongo ID
    update_data.pop('_id', None)
    update_data.pop('user_id', None)

    try:
        result = mongo.db.personal_passwords.update_one(
            {'_id': ObjectId(password_id), 'user_id': ObjectId(user_id)}, # Double check ownership
            {'$set': update_data}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to update personal password ID {password_id} for user {user_id}: {e}")
        return False

def delete_personal_password(password_id: str, user_id: str) -> bool:
     # Ensure user owns this password before deleting
    try:
        if not ObjectId.is_valid(password_id) or not ObjectId.is_valid(user_id): return False
        result = mongo.db.personal_passwords.delete_one({
            '_id': ObjectId(password_id),
            'user_id': ObjectId(user_id)
        })
        return result.deleted_count > 0
    except Exception as e:
        print(f"--- [models.py] ERROR: Failed to delete personal password ID {password_id} for user {user_id}: {e}")
        return False

# --- CORRECTED TYPE HINT BELOW ---
def get_decrypted_password(item_type: str, item_id: str, user_id: Optional[str] = None) -> Optional[str]: # Changed from 'str | None'
# --- END CORRECTION ---
    """Safely retrieves and decrypts a password for a specific item."""
    item: Optional[VaultItem] = None
    encrypted_pw: Optional[str] = None

    # Basic validation
    if not item_id or not ObjectId.is_valid(item_id):
         print(f"--- [models.py] ERROR: Invalid item_id '{item_id}' for get_decrypted_password.")
         return None
    if item_type == 'personal' and (not user_id or not ObjectId.is_valid(user_id)):
        print(f"--- [models.py] ERROR: Invalid or missing user_id '{user_id}' for personal item_type.")
        return None

    try:
        if item_type == 'server':
            item = mongo.db.servers.find_one({'_id': ObjectId(item_id)})
        elif item_type == 'laptop':
            item = mongo.db.laptops.find_one({'_id': ObjectId(item_id)})
        elif item_type == 'personal':
            # User ID check already happened, but check again for safety
            if user_id:
                 item = mongo.db.personal_passwords.find_one({'_id': ObjectId(item_id), 'user_id': ObjectId(user_id)})
        else:
            print(f"--- [models.py] ERROR: Invalid item_type '{item_type}' for get_decrypted_password.")
            return None # Invalid type

        if item:
            encrypted_pw = item.get('encrypted_password')
            if encrypted_pw:
                # Decrypt_string already handles errors and returns Optional[str]
                return decrypt_string(encrypted_pw)
            else:
                 print(f"--- [models.py] Warning: No 'encrypted_password' field found for {item_type} {item_id}.")
                 return None # No password field found
        else:
             print(f"--- [models.py] Warning: Item not found for {item_type} {item_id} (or permission denied for personal).")
             return None # Item not found or doesn't belong to user

    except Exception as e:
        print(f"--- [models.py] ERROR: Failed during get_decrypted_password for {item_type} {item_id}: {e}")
        # Optionally flash a generic error? Be careful about revealing too much.
        # flash("An internal error occurred while retrieving the password.", "danger")
        return None