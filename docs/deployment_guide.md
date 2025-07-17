# VirusTotal File Scanner Deployment Guide

This guide provides detailed instructions for deploying the VirusTotal File Scanner application using Docker.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Docker Configuration](#docker-configuration)
4. [Environment Variables](#environment-variables)
5. [Deployment Steps](#deployment-steps)
6. [Health Checks](#health-checks)
7. [Scaling](#scaling)
8. [Backup and Recovery](#backup-and-recovery)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

Before deploying the VirusTotal File Scanner, ensure you have the following:

- Docker Engine (version 20.10.0 or higher)
- Docker Compose (version 2.0.0 or higher)
- Git (for cloning the repository)
- A VirusTotal API key (register at [VirusTotal](https://www.virustotal.com/))
- At least 2GB of free RAM
- At least 10GB of free disk space

## System Requirements

The application consists of two main services:

1. **Web Application (webapp)**: Combines the Flask backend and React frontend
   - CPU: 1-2 cores
   - Memory: 1GB minimum, 2GB recommended
   - Disk: 1GB for application, plus storage for uploaded files

2. **Database (db)**: PostgreSQL database for storing application data
   - CPU: 1 core
   - Memory: 512MB minimum, 1GB recommended
   - Disk: 5GB minimum for database files

## Docker Configuration

The application uses Docker Compose to manage multiple containers. The main components are:

### Web Application Container

- **Base Image**: Python 3.9 with Node.js for frontend building
- **Web Server**: Nginx for serving static files
- **Application Server**: Gunicorn for running the Flask application
- **Exposed Port**: 8080 (mapped to container port 80)
- **Volumes**: Mounted volume for uploaded files
- **Dependencies**: PostgreSQL database

### Database Container

- **Base Image**: PostgreSQL 14 Alpine
- **Exposed Port**: 5432 (internal only)
- **Volumes**: Mounted volume for database data
- **Initialization**: Automatic schema creation via init-db.sql

## Environment Variables

Create a `.env` file in the project root with the following variables:

```
# Database configuration
POSTGRES_PASSWORD=your_secure_password_here

# Application configuration
SECRET_KEY=your_secret_key_here
FLASK_ENV=production

# Optional: VirusTotal API configuration
# VIRUSTOTAL_API_URL=https://www.virustotal.com/api/v3
```

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| POSTGRES_PASSWORD | Password for the PostgreSQL database | `your_secure_password_here` |
| SECRET_KEY | Secret key for JWT token generation and encryption | `your_secret_key_here` |

### Optional Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| FLASK_ENV | Flask environment (development/production) | `production` | `development` |
| VIRUSTOTAL_API_URL | VirusTotal API URL | `https://www.virustotal.com/api/v3` | `https://www.virustotal.com/api/v3` |
| MAX_CONTENT_LENGTH | Maximum file upload size in bytes | `50000000` (50MB) | `100000000` (100MB) |

## Deployment Steps

Follow these steps to deploy the VirusTotal File Scanner:

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/virustotal-file-scanner.git
cd virustotal-file-scanner
```

### 2. Create Environment File

```bash
cp .env.example .env
```

Edit the `.env` file and set the required environment variables:

```bash
# Use a strong password for the database
POSTGRES_PASSWORD=your_secure_password_here

# Generate a random secret key
SECRET_KEY=$(openssl rand -hex 32)
```

### 3. Create Data Directories

```bash
mkdir -p data/postgres
mkdir -p data/uploads
chmod 777 data/uploads
```

### 4. Build and Start the Containers

```bash
docker-compose build
docker-compose up -d
```

### 5. Verify Deployment

Check if the containers are running:

```bash
docker-compose ps
```

You should see both the `webapp` and `db` containers running.

### 6. Access the Application

Open your web browser and navigate to:

```
http://localhost:8080
```

## Health Checks

The Docker Compose configuration includes health checks for both services:

### Web Application Health Check

- **Command**: `curl -f http://localhost:80/health`
- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Retries**: 3
- **Start Period**: 40 seconds

### Database Health Check

- **Command**: `pg_isready -U postgres`
- **Interval**: 10 seconds
- **Timeout**: 5 seconds
- **Retries**: 5
- **Start Period**: 10 seconds

You can check the health status of the containers using:

```bash
docker-compose ps
```

## Scaling

### Horizontal Scaling

To scale the web application horizontally:

1. Add a load balancer in front of multiple webapp instances
2. Update the Docker Compose file to support multiple webapp instances
3. Ensure the database can handle increased connections

Example Docker Compose command for scaling:

```bash
docker-compose up -d --scale webapp=3
```

Note: Additional configuration for load balancing would be required.

### Vertical Scaling

To increase resources for a container:

1. Stop the containers:
   ```bash
   docker-compose down
   ```

2. Edit the Docker Compose file to add resource constraints:
   ```yaml
   services:
     webapp:
       deploy:
         resources:
           limits:
             cpus: '2'
             memory: 2G
   ```

3. Restart the containers:
   ```bash
   docker-compose up -d
   ```

## Backup and Recovery

### Database Backup

To backup the PostgreSQL database:

```bash
docker-compose exec db pg_dump -U postgres virustotal_scanner > backup_$(date +%Y%m%d).sql
```

### Database Restore

To restore from a backup:

```bash
cat backup_20230101.sql | docker-compose exec -T db psql -U postgres virustotal_scanner
```

### File Backup

To backup uploaded files:

```bash
tar -czf uploads_backup_$(date +%Y%m%d).tar.gz data/uploads/
```

### File Restore

To restore uploaded files:

```bash
tar -xzf uploads_backup_20230101.tar.gz -C /
```

## Troubleshooting

### Common Issues

#### Container Fails to Start

Check the container logs:

```bash
docker-compose logs webapp
docker-compose logs db
```

#### Database Connection Issues

Verify the database is running and accessible:

```bash
docker-compose exec webapp ping db
docker-compose exec db psql -U postgres -c "SELECT 1"
```

#### File Upload Problems

Check permissions on the uploads directory:

```bash
ls -la data/uploads
```

Ensure the directory has the correct permissions (777 for development, more restricted for production).

#### Memory Issues

If the containers are being killed due to memory constraints, increase the available memory:

```bash
docker-compose down
# Edit docker-compose.yml to add memory limits
docker-compose up -d
```

### Viewing Logs

To view logs for debugging:

```bash
# View all logs
docker-compose logs

# View logs for a specific service
docker-compose logs webapp

# Follow logs in real-time
docker-compose logs -f

# View last 100 lines
docker-compose logs --tail=100
```

### Restarting Services

If you need to restart a service:

```bash
# Restart a specific service
docker-compose restart webapp

# Restart all services
docker-compose restart
```

### Rebuilding After Changes

If you make changes to the application code:

```bash
# Rebuild and restart containers
docker-compose up -d --build
```