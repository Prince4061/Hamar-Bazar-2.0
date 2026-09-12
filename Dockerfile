# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5001
ENV TZ=Asia/Kolkata

# Set work directory
WORKDIR /app

# Install system dependencies & timezone configuration
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . /app/

# Expose port 5001
EXPOSE 5001

# Gunicorn: 3 workers x 4 threads, workers recycled every ~800 requests (memory safety), 60s request timeout, logs to stdout
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "3", "--threads", "4", \
     "--timeout", "60", "--graceful-timeout", "30", "--keep-alive", "5", \
     "--max-requests", "800", "--max-requests-jitter", "200", \
     "--worker-tmp-dir", "/dev/shm", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
