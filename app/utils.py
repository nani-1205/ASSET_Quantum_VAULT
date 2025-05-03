import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app, flash
# --- Added Import ---
from typing import Optional, Union # Use Optional for Python < 3.10 compatibility
# --- End Import ---

# --- Encryption ---
# Use Fernet for symmetric encryption (requires a single key)

def get_fernet():
    """Creates a Fernet instance using the key from config."""
    key = current_app.config.get('ENCRYPTION_KEY_BYTES') # Use .get() for safety
    if not key:
        print("--- [utils.py] ERROR: Encryption key bytes not found in config.")
        raise ValueError("Encryption key bytes not found in config.")
    return Fernet(key)

def encrypt_data(data_bytes: bytes) -> bytes:
    """Encrypts bytes using Fernet."""
    if not isinstance(data_bytes, bytes):
        raise TypeError("Data to encrypt must be bytes.")
    f = get_fernet()
    return f.encrypt(data_bytes)

def decrypt_data(encrypted_data_bytes: bytes) -> Optional[bytes]: # Changed return type hint
    """Decrypts bytes using Fernet. Returns None on failure."""
    if not isinstance(encrypted_data_bytes, bytes):
        # flash("Invalid data format for decryption.", "danger") # Flashing here might be too noisy
        print("--- [utils.py] Warning: Attempted to decrypt non-bytes data.")
        return None # Or raise TypeError
    f = get_fernet()
    try:
        return f.decrypt(encrypted_data_bytes)
    except InvalidToken:
        # This can happen if the key is wrong or the data is corrupted/tampered
        flash("Decryption failed. Data might be corrupted or the key is incorrect.", "danger")
        print("--- [utils.py] Error: Decryption failed (InvalidToken).")
        return None
    except Exception as e:
        # Catch other potential errors during decryption
        flash(f"An unexpected error occurred during decryption: {e}", "danger")
        print(f"--- [utils.py] Error: Unexpected decryption error: {e}")
        return None

def encrypt_string(text: str) -> str:
    """Encrypts a string and returns a base64 encoded string."""
    encrypted_bytes = encrypt_data(text.encode('utf-8'))
    # Store as base64 string for easier handling in JSON/DB
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

# --- CORRECTED TYPE HINT BELOW ---
def decrypt_string(encrypted_text: str) -> Optional[str]: # Changed from 'str | None'
# --- END CORRECTION ---
    """Decrypts a base64 encoded string back to the original string."""
    try:
        # Ensure input is bytes before decoding
        if isinstance(encrypted_text, str):
             encrypted_b64_bytes = encrypted_text.encode('utf-8')
        else:
             # Handle cases where non-string might be passed, though type hint is str
             print(f"--- [utils.py] Warning: decrypt_string received non-string input type: {type(encrypted_text)}")
             return None

        encrypted_bytes = base64.urlsafe_b64decode(encrypted_b64_bytes)
        decrypted_bytes = decrypt_data(encrypted_bytes)
        if decrypted_bytes:
            return decrypted_bytes.decode('utf-8')
        # If decrypt_data returned None, we also return None
        return None
    except (ValueError, TypeError, base64.binascii.Error) as e:
        # Handle errors if the input is not valid base64 or other issues
        flash("Invalid format for encrypted data.", "danger")
        print(f"--- [utils.py] Error: Failed to decode base64 or decrypt: {e}")
        return None
    except Exception as e:
        # Catch unexpected errors during the process
        flash(f"An unexpected error occurred during string decryption: {e}", "danger")
        print(f"--- [utils.py] Error: Unexpected error in decrypt_string: {e}")
        return None


# --- Role Checking Decorators ---
# (Moved here for better organization)
from functools import wraps
from flask_login import current_user
from flask import abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin_or_temp():
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def temp_admin_check(f):
    """Optional: Decorator to check/revoke expired temp admin status"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and getattr(current_user, 'is_temp_admin', False): # Safer check
            # Ensure the check_and_revoke method exists before calling
            if hasattr(current_user, 'check_and_revoke_temp_admin'):
                 current_user.check_and_revoke_temp_admin()
            else:
                 print(f"--- [utils.py] Warning: User object {current_user.id} lacks 'check_and_revoke_temp_admin' method.")
        return f(*args, **kwargs)
    return decorated_function

# --- Reporting ---
# (Basic structure, implement actual report generation later)
import io
try:
    from openpyxl import Workbook
except ImportError:
    Workbook = None # Handle gracefully if not installed
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
except ImportError:
    # Handle gracefully if not installed
    letter = None
    SimpleDocTemplate = None
    Paragraph = None
    Spacer = None
    getSampleStyleSheet = None


def generate_xlsx_report(data):
    """Generates an XLSX report from laptop software data."""
    if Workbook is None:
        raise ImportError("The 'openpyxl' library is required to generate XLSX reports.")

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Laptop Software Inventory"

    # Headers
    headers = ["Laptop ID", "Employee Name", "Username", "Installed Software"]
    sheet.append(headers)

    # Data
    for laptop in data:
        # Ensure software list is iterable and joinable, handle None or non-list
        software_list_raw = laptop.get('installed_software', [])
        if isinstance(software_list_raw, list):
             software_list = ", ".join(software_list_raw)
        elif isinstance(software_list_raw, str): # Handle if it's accidentally stored as string
             software_list = software_list_raw
        else:
             software_list = "N/A"

        row = [
            laptop.get('laptop_id', 'N/A'),
            laptop.get('employee_name', 'N/A'),
            laptop.get('username', 'N/A'),
            software_list
        ]
        sheet.append(row)

    # Save to a BytesIO buffer
    buffer = io.BytesIO()
    workbook.save(buffer)
    buffer.seek(0)
    return buffer

def generate_pdf_report(data):
    """Generates a PDF report from laptop software data."""
    if SimpleDocTemplate is None:
         raise ImportError("The 'reportlab' library is required to generate PDF reports.")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title = "Laptop Software Inventory Report"
    try:
        story.append(Paragraph(title, styles['h1']))
    except KeyError:
         print("--- [utils.py] Warning: ReportLab style 'h1' not found, using 'h1'.")
         story.append(Paragraph(title, styles['h1'])) # Fallback or adjust style name

    story.append(Spacer(1, 12))

    for laptop in data:
        try:
            story.append(Paragraph(f"<b>Laptop ID:</b> {laptop.get('laptop_id', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"<b>Employee Name:</b> {laptop.get('employee_name', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"<b>Username:</b> {laptop.get('username', 'N/A')}", styles['Normal']))

            software = laptop.get('installed_software', [])
            if software and isinstance(software, list): # Ensure it's a list
                story.append(Paragraph("<b>Installed Software:</b>", styles['Normal']))
                for sw in software:
                    # Ensure sw is a string before adding
                    story.append(Paragraph(f"- {str(sw)}", styles['Normal']))
            elif software: # If not list but not empty, display as is
                 story.append(Paragraph("<b>Installed Software:</b>", styles['Normal']))
                 story.append(Paragraph(f"- {str(software)}", styles['Normal']))
            else:
                story.append(Paragraph("<b>Installed Software:</b> None listed", styles['Normal']))

            story.append(Spacer(1, 12)) # Add space between entries
        except KeyError:
            print("--- [utils.py] Warning: ReportLab style 'Normal' or 'h1' not found.")
            # Handle error - maybe use a default style or skip paragraph
            continue # Skip this laptop entry if styles are missing

    try:
        doc.build(story)
        buffer.seek(0)
        return buffer
    except Exception as e:
         print(f"--- [utils.py] Error building PDF report: {e}")
         # Optionally re-raise or return None/error indicator
         raise e