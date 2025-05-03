import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app, flash

# --- Encryption ---
# Use Fernet for symmetric encryption (requires a single key)

def get_fernet():
    """Creates a Fernet instance using the key from config."""
    key = current_app.config['ENCRYPTION_KEY_BYTES']
    if not key:
        raise ValueError("Encryption key not found in config.")
    return Fernet(key)

def encrypt_data(data_bytes: bytes) -> bytes:
    """Encrypts bytes using Fernet."""
    if not isinstance(data_bytes, bytes):
        raise TypeError("Data to encrypt must be bytes.")
    f = get_fernet()
    return f.encrypt(data_bytes)

def decrypt_data(encrypted_data_bytes: bytes) -> bytes:
    """Decrypts bytes using Fernet. Returns None on failure."""
    if not isinstance(encrypted_data_bytes, bytes):
        # flash("Invalid data format for decryption.", "danger") # Flashing here might be too noisy
        print("Warning: Attempted to decrypt non-bytes data.")
        return None # Or raise TypeError
    f = get_fernet()
    try:
        return f.decrypt(encrypted_data_bytes)
    except InvalidToken:
        # This can happen if the key is wrong or the data is corrupted/tampered
        flash("Decryption failed. Data might be corrupted or the key is incorrect.", "danger")
        print("Error: Decryption failed (InvalidToken).")
        return None
    except Exception as e:
        # Catch other potential errors during decryption
        flash(f"An unexpected error occurred during decryption: {e}", "danger")
        print(f"Error: Unexpected decryption error: {e}")
        return None

def encrypt_string(text: str) -> str:
    """Encrypts a string and returns a base64 encoded string."""
    encrypted_bytes = encrypt_data(text.encode('utf-8'))
    # Store as base64 string for easier handling in JSON/DB
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

def decrypt_string(encrypted_text: str) -> str | None:
    """Decrypts a base64 encoded string back to the original string."""
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
        decrypted_bytes = decrypt_data(encrypted_bytes)
        if decrypted_bytes:
            return decrypted_bytes.decode('utf-8')
        return None
    except (ValueError, TypeError, base64.binascii.Error) as e:
        # Handle errors if the input is not valid base64 or other issues
        flash("Invalid format for encrypted data.", "danger")
        print(f"Error: Failed to decode base64 or decrypt: {e}")
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
        if current_user.is_authenticated and current_user.is_temp_admin:
            current_user.check_and_revoke_temp_admin()
        return f(*args, **kwargs)
    return decorated_function

# --- Reporting ---
# (Basic structure, implement actual report generation later)
import io
from openpyxl import Workbook
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_xlsx_report(data):
    """Generates an XLSX report from laptop software data."""
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Laptop Software Inventory"

    # Headers
    headers = ["Laptop ID", "Employee Name", "Username", "Installed Software"]
    sheet.append(headers)

    # Data
    for laptop in data:
        software_list = ", ".join(laptop.get('installed_software', [])) # Combine software into one cell
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
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title = "Laptop Software Inventory Report"
    story.append(Paragraph(title, styles['h1']))
    story.append(Spacer(1, 12))

    for laptop in data:
        story.append(Paragraph(f"<b>Laptop ID:</b> {laptop.get('laptop_id', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Employee Name:</b> {laptop.get('employee_name', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Username:</b> {laptop.get('username', 'N/A')}", styles['Normal']))
        software = laptop.get('installed_software', [])
        if software:
            story.append(Paragraph("<b>Installed Software:</b>", styles['Normal']))
            for sw in software:
                story.append(Paragraph(f"- {sw}", styles['Normal']))
        else:
            story.append(Paragraph("<b>Installed Software:</b> None listed", styles['Normal']))
        story.append(Spacer(1, 12)) # Add space between entries

    doc.build(story)
    buffer.seek(0)
    return buffer