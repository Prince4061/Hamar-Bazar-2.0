# 🚀 Hostinger Docker Deployment Guide | Hamar Bazar 2.0

This guide explains step-by-step how to build your Docker image, push it to **Docker Hub**, and deploy the application on **Hostinger VPS** using a clean, production-ready Docker Compose setup.

---

## 🏗️ Deployment Architecture Overview
To host Hamar Bazar 2.0 on Hostinger:
1. **Local Build**: We package the app into a Docker image and push it to Docker Hub.
2. **VPS Deployment**: On your Hostinger VPS, we use a single `docker-compose.yml` file to pull the image from Docker Hub and run it.
3. **Data Persistence**: We map Docker volumes for the SQLite database (`/data`) and user uploads (`/app/static/uploads`) so that your catalog, user records, and uploaded files (profile pics, payments, prescriptions) are never lost during updates.

---

## 🐋 Part 1: Build & Push the Docker Image

Ensure Docker Desktop is open and running on your local machine.

### Step 1: Login to Docker Hub
Open your terminal (PowerShell or command prompt) in the project folder and run:
```bash
docker login
```
*Enter your Docker Hub username and password when prompted.*

### Step 2: Build the Docker Image
Build the Docker image locally. Replace `your_dockerhub_username` with your actual Docker Hub username (e.g., `prince4061`):
```bash
docker build -t your_dockerhub_username/hamar-bazar-2.0:latest .
```

### Step 3: Push the Image to Docker Hub
Push the compiled image to your public or private Docker Hub repository:
```bash
docker push your_dockerhub_username/hamar-bazar-2.0:latest
```

---

## 🌐 Part 2: Deploying on Hostinger VPS

### Step 1: Access your Hostinger VPS
Connect to your Hostinger VPS via SSH using your terminal:
```bash
ssh root@<YOUR_VPS_IP>
```

### Step 2: Set up the Project Directory
Create a dedicated folder for your deployment on the VPS:
```bash
mkdir -p /opt/hamar-bazar
cd /opt/hamar-bazar
```

### Step 3: Create the `docker-compose.yml` on the VPS
Create a new file named `docker-compose.yml` inside that directory using a text editor (like `nano`):
```bash
nano docker-compose.yml
```
Copy and paste the following production configuration:

```yaml
version: '3.8'

services:
  web:
    image: your_dockerhub_username/hamar-bazar-2.0:latest  # Replace with your Docker Hub username
    container_name: hamar-bazar-web
    ports:
      - "80:5001"  # Binds the VPS port 80 (HTTP) to container port 5001
    volumes:
      - hamar_bazar_data:/data
      - hamar_bazar_uploads:/app/static/uploads
    environment:
      - DATABASE_PATH=/data/marketplace.db
      - FLASK_SECRET_KEY=hyperlocal_monopolistic_secret_key_12345  # Change to a secure key
    restart: always

volumes:
  hamar_bazar_data:
  hamar_bazar_uploads:
```
*Press `Ctrl+O` then `Enter` to save, and `Ctrl+X` to exit nano.*

### Step 4: Run the Application
Start the container service in the background:
```bash
docker compose up -d
```
*If you are running an older version of docker on the VPS, you may need to use `docker-compose up -d` (with a hyphen).*

---

## 🛠️ Management & Maintenance Commands

| Action | Command | Description |
| :--- | :--- | :--- |
| **Check App Status** | `docker ps` | View running containers, their uptime, and ports. |
| **Check Logs** | `docker logs -f hamar-bazar-web` | View real-time error logs and requests. |
| **Stop App** | `docker compose down` | Stops the app container (keeps DB and upload data). |
| **Update App** | `docker compose pull && docker compose up -d` | Pulls the newest image from Docker Hub and updates. |
| **Full Clean Reset** | `docker compose down -v` | Deletes all containers AND completely resets the database & uploads. |

---

## 💡 Important Database Seeding Notes
* When the container starts on Hostinger for the first time, it will detect that the mounted volume `/data` is empty. 
* The application will **automatically initialize, create tables, and seed the database** with the default shops, products, and historical analytics.
* **Backups / Restores**: You can export the database or upload custom `.db` files directly through the admin dashboard inside the app.
