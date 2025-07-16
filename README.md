# VirusTotal File Scanner

A Docker-based web application that allows users to scan files for malicious content using the VirusTotal API.

## Features

- API key management for VirusTotal
- File upload and scanning
- Detailed scan results with filtering and sorting
- Docker deployment for easy setup
- Secure handling of files and API keys

## Project Structure

```
virustotal-file-scanner/
├── backend/             # Python Flask backend
│   ├── api/             # API endpoints
│   ├── models/          # Database models
│   ├── services/        # Business logic and external services
│   ├── tests/           # Unit and integration tests
│   └── config/          # Configuration files
├── frontend/            # React frontend
│   ├── public/          # Static files
│   └── src/             # Source code
│       ├── components/  # React components
│       ├── services/    # API services
│       ├── pages/       # Page components
│       ├── utils/       # Utility functions
│       └── assets/      # Images, fonts, etc.
└── docker/              # Docker configuration files
```

## Getting Started

### Prerequisites

- Docker and Docker Compose installed on your system
- VirusTotal API key (register at [VirusTotal](https://www.virustotal.com/))

### Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/virustotal-file-scanner.git
   cd virustotal-file-scanner
   ```

2. Create a `.env` file from the example:
   ```
   cp .env.example .env
   ```

3. Edit the `.env` file and set your secure password and secret key:
   ```
   POSTGRES_PASSWORD=your_secure_password_here
   SECRET_KEY=your_secret_key_here
   ```

4. Build and start the containers:
   ```
   docker-compose up -d
   ```

5. Access the application at http://localhost:8080

### Persistent Storage

The application uses Docker volumes for persistent storage:

- **Database data**: Stored in `./data/postgres` directory
- **Uploaded files**: Stored in `./data/uploads` directory

These volumes ensure that your data persists even if the containers are stopped or removed.

## License

This project is licensed under the MIT License - see the LICENSE file for details.