# Use an official Python runtime as a parent image
# Using a specific version and slim variant for smaller size
FROM python:3.9-slim-bullseye

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE 1  # Prevent python from writing pyc files
ENV PYTHONUNBUFFERED 1        # Force stdout/stderr streams to be unbuffered (good for logs)

# Set the working directory in the container
WORKDIR /app

# Install system dependencies (if any - less likely needed with slim but good practice)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN python -m pip install --upgrade pip

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
# --no-cache-dir reduces image size
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user and group
# Running as non-root is a security best practice
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser

# Copy the rest of the application code into the container
# Ensure this comes AFTER dependency installation for better caching
COPY . .

# Change ownership of the app directory to the non-root user
# Must happen AFTER copying the code
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the port that Gunicorn will run on
EXPOSE 5000

# Define the command to run the application using Gunicorn
# Adjust the number of workers (-w) based on your server's CPU resources (e.g., 2 * cores + 1)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "-w", "4", "run:app"]