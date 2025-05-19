# ASSET Quantum VAULT

ASSET Quantum VAULT is a Flask-based web application designed for secure password management and asset tracking. It allows administrators to manage server credentials, laptop details (including installed software), and grant temporary administrative access. Users can also sign up to store their own personal passwords securely.

## Features

*   **User Authentication:**
    *   User signup and login.
    *   First registered user becomes the admin.
    *   Password hashing for user accounts.
*   **Admin Password Vault:**
    *   Store server credentials (name, IP, login, password, notes).
    *   Store laptop details (ID, employee, username, password, installed software, notes).
    *   View, Add, Edit, and Delete vault entries.
    *   Secure password encryption for vault entries.
    *   Copy passwords to clipboard (client-side).
*   **Personal Password Vault:**
    *   Users can store their own website/service passwords securely.
    *   View, Add, Edit, and Delete personal passwords.
*   **Temporary Admin Access:**
    *   Permanent admins can grant temporary administrative privileges to other users.
    *   Option to set an expiry time for temporary access.
*   **Reporting (Admin):**
    *   Generate reports on installed software across laptops.
    *   Export reports in PDF or XLSX format.
*   **Database:**
    *   Uses MongoDB for data storage.
    *   Checks for database existence on startup and can create the initial admin user.
*   **Security:**
    *   Strong encryption for stored passwords (using Fernet).
    *   CSRF protection for forms.

## Prerequisites

*   Python 3.9+
*   MongoDB Server (ensure it's running and accessible)
*   `pip` (Python package installer)
*   A virtual environment tool (like `venv`) is highly recommended.

## Setup and Installation

1.  **Clone the Repository (if applicable):**
    ```bash
    git clone https://github.com/nani-1205/ASSET_Quantum_VAULT.git
    cd ASSET_Quantum_VAULT
    ```
    If you don't have a Git repository, simply ensure all the project files are in a directory named `ASSET_Quantum_VAULT`.

2.  **Create and Activate a Virtual Environment:**
    It's highly recommended to use a virtual environment to manage dependencies.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    # venv\Scripts\activate    # On Windows
    ```

3.  **Install Dependencies:**
    Install all required Python packages listed in `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**
    The application uses a `.env` file in the project root directory (`ASSET_Quantum_VAULT/`) to store sensitive configurations.
    *   Create a file named `.env`.
    *   Copy the following content into it and **modify the placeholder values**:

    ```ini
    # Flask Configuration
    SECRET_KEY='YOUR_GENERATED_FLASK_SECRET_KEY' # Generate using: python -c 'import os; print(os.urandom(24).hex())'
    FLASK_ENV=development # Use 'production' for deployment
    FLASK_DEBUG=1         # Set to 0 in production

    # MongoDB Configuration
    MONGO_USERNAME=your_mongo_user       # Replace with your MongoDB username
    MONGO_PASSWORD=your_mongo_password   # Replace with your MongoDB password
    MONGO_HOST=your_mongo_ip_or_hostname # Replace with your MongoDB host/IP (e.g., localhost or 127.0.0.1)
    MONGO_PORT=27017                     # Replace with your MongoDB port
    MONGO_DB_NAME=asset_quantum_vault    # Desired database name
    MONGO_AUTH_DB=admin                  # MongoDB authentication database (usually 'admin' or the same as MONGO_DB_NAME if auth is on the DB itself)

    # Encryption Key - VERY IMPORTANT!
    # Generate using: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Store this key securely and back it up! If lost, encrypted data is unrecoverable.
    ENCRYPTION_KEY='YOUR_GENERATED_FERNET_ENCRYPTION_KEY'

    # Admin User (for first run if database is empty)
    ADMIN_USERNAME=admin
    ADMIN_PASSWORD=your_strong_initial_admin_password # CHANGE THIS!
    ```

    *   **Generate `SECRET_KEY`:** Run `python -c 'import os; print(os.urandom(24).hex())'` in your terminal and paste the output.
    *   **Generate `ENCRYPTION_KEY`:** Run `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` in your terminal and paste the output. **Backup this key securely!**
    *   Update MongoDB connection details (`MONGO_USERNAME`, `MONGO_PASSWORD`, `MONGO_HOST`, `MONGO_PORT`, `MONGO_DB_NAME`, `MONGO_AUTH_DB`).
    *   Set a strong initial `ADMIN_PASSWORD`.

5.  **Ensure MongoDB is Running:**
    Start your MongoDB server and ensure it's accessible with the credentials specified in `.env`.

## Running the Application

1.  **Activate the Virtual Environment (if not already active):**
    ```bash
    source venv/bin/activate  # On Linux/macOS
    # venv\Scripts\activate    # On Windows
    ```

2.  **Run the Flask Development Server:**
    From the project root directory (`ASSET_Quantum_VAULT/`):
    ```bash
    flask run
    ```
    Or, if you prefer using `python run.py`:
    ```bash
    python run.py
    ```

3.  **Access the Application:**
    Open your web browser and go to `http://127.0.0.1:5000` (or the address shown in your terminal).

4.  **First Login:**
    *   The first time you run the application with an empty database, an admin user will be created with the `ADMIN_USERNAME` and `ADMIN_PASSWORD` you set in the `.env` file.
    *   Log in with these credentials.
    *   **It is highly recommended to change this default admin password immediately** (currently, a "Change Password" feature needs to be implemented by the user).

