from app import create_app

app = create_app()

if __name__ == '__main__':
    # Use Flask's built-in server for development only.
    # For production, use a production-ready WSGI server like Gunicorn or uWSGI.
    # Example: gunicorn --bind 0.0.0.0:5000 run:app
    app.run(host='0.0.0.0', port=5000) # Debug mode will be controlled by FLASK_DEBUG in .env