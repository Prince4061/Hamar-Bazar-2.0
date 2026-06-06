FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install build dependencies (often useful for python wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Configure SQLite data directory volume for database persistence
ENV DATABASE_PATH=/data/marketplace.db
RUN mkdir -p /data
VOLUME /data

# Expose the Flask port
EXPOSE 5001

# Run the Flask app
CMD ["python", "app.py"]
