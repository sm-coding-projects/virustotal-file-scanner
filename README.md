# VirusTotal File Scanner

A secure, Docker-based web application that allows users to scan files for malicious content using the VirusTotal API. This application provides a user-friendly interface for managing API keys, uploading files, and analyzing scan results.

![VirusTotal File Scanner](https://img.shields.io/badge/VirusTotal-File%20Scanner-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)
![React](https://img.shields.io/badge/Frontend-React-blue)
![Flask](https://img.shields.io/badge/Backend-Flask-green)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-blue)

## Features

### Core Functionality
- **User Authentication**: Secure registration and login system with JWT tokens
- **API Key Management**: Securely store and manage VirusTotal API keys
- **File Upload**: Upload files for scanning with automatic hash calculation
- **File Scanning**: Scan files using the VirusTotal API
- **Scan Results**: View detailed scan results with filtering and sorting options
- **Export Options**: Export scan results in various formats (JSON, CSV, PDF)

### Security Features
- **Encrypted Storage**: API keys are encrypted in the database
- **Secure File Handling**: Files are stored securely with proper permissions
- **Rate Limiting**: Protection against abuse and API rate limits
- **Input Validation**: Comprehensive validation of all user inputs
- **Content Security**: Security headers and protection against common web vulnerabilities

### User Experience
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Accessibility**: WCAG 2.1 compliant with screen reader support
- **Intuitive Interface**: Clean, modern UI with clear navigation
- **Real-time Feedback**: Progress indicators and status updates
- **Error Handling**: User-friendly error messages and recovery options

## Architecture

The application follows a modern microservices architecture using Docker containers:

### Backend (Python Flask)
- RESTful API endpoints for all functionality
- PostgreSQL database for data storage
- JWT authentication for secure API access
- Comprehensive test suite with high coverage

### Frontend (React)
- Modern React application with TypeScript
- Component-based architecture
- State management with React hooks
- Responsive design for all device sizes
- Accessibility features built-in

### Docker Infrastructure
- Multi-container setup with Docker Compose
- Nginx for serving static files and reverse proxy
- PostgreSQL database container
- Health checks and automatic recovery
- Volume mounts for persistent data

## Project Structure

```
virustotal-file-scanner/
├── backend/                # Python Flask backend
│   ├── api/                # API endpoints
│   │   ├── auth.py         # Authentication endpoints
│   │   ├── files.py        # File management endpoints
│   │   ├── keys.py         # API key management endpoints
│   │   ├── scan.py         # Scan management endpoints
│   │   └── routes.py       # Route configuration
│   ├── models/             # Database models
│   ├── services/           # Business logic and external services
│   ├── utils/              # Utility functions
│   ├── config/             # Configuration files
│   └── tests/              # Unit and integration tests
├── frontend/               # React frontend
│   ├── public/             # Static files
│   └── src/                # Source code
│       ├── components/     # React components
│       ├── services/       # API services
│       ├── pages/          # Page components
│       ├── utils/          # Utility functions
│       └── store/          # State management
├── docker/                 # Docker configuration files
│   ├── Dockerfile.webapp   # Web application Dockerfile
│   ├── Dockerfile.db       # Database Dockerfile
│   ├── nginx.conf          # Nginx configuration
│   ├── init-db.sql         # Database initialization script
│   └── start.sh            # Container startup script
├── docs/                   # Documentation
│   ├── api_documentation.md # API documentation
│   ├── deployment_guide.md  # Deployment guide
│   └── user_guide.md        # User guide
└── data/                   # Data directories (created during setup)
    ├── postgres/           # PostgreSQL data
    ├── uploads/            # Uploaded files
    └── backups/            # Database backups
```

## Getting Started

### Prerequisites

- Docker Engine (version 20.10.0 or higher)
- Docker Compose (version 2.0.0 or higher)
- Git (for cloning the repository)
- A VirusTotal API key (register at [VirusTotal](https://www.virustotal.com/))
- At least 2GB of free RAM
- At least 10GB of free disk space

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/virustotal-file-scanner.git
   cd virustotal-file-scanner
   ```

2. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   ```

3. Edit the `.env` file and set your secure password and secret key:
   ```
   POSTGRES_PASSWORD=your_secure_password_here
   SECRET_KEY=your_secret_key_here
   ```

4. Create data directories:
   ```bash
   mkdir -p data/postgres
   mkdir -p data/uploads
   mkdir -p data/backups
   chmod 750 data/uploads
   ```

5. Build and start the containers:
   ```bash
   docker-compose build
   docker-compose up -d
   ```

6. Access the application at http://localhost:8080

### Production Deployment

For production environments, use the production Docker Compose configuration:

```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

This enables additional features like:
- Automatic database backups
- Increased resource limits
- Enhanced logging configuration
- Multiple webapp instances

See the [Deployment Guide](docs/deployment_guide.md) for detailed instructions.

## Usage

### User Registration and Login

1. Open the application in your web browser
2. Click "Register" to create a new account
3. Fill in your username, email, and password
4. Log in with your credentials

### Adding a VirusTotal API Key

1. Navigate to the "API Keys" section
2. Click "Add API Key"
3. Enter a name for your key and paste your VirusTotal API key
4. Click "Save" to store your API key

### Uploading and Scanning Files

1. Navigate to the "Files" section
2. Click "Upload File" or drag and drop files
3. Select the file(s) you want to scan
4. Files will be automatically scanned if you have an active API key

### Viewing Scan Results

1. Navigate to the "Scan Results" section
2. Click on a scan to view detailed results
3. Use filters and sorting options to find specific results
4. Export results in your preferred format

For detailed usage instructions, see the [User Guide](docs/user_guide.md).

## API Documentation

The application provides a comprehensive REST API for all functionality. See the [API Documentation](docs/api_documentation.md) for detailed information about available endpoints, request/response formats, and authentication.

## Accessibility

The application is designed to be accessible to all users, including those with disabilities. Key accessibility features include:

- ARIA attributes for screen reader support
- Keyboard navigation capabilities
- High contrast and reduced motion support
- Comprehensive focus management
- Screen reader announcements

For detailed information about accessibility features, see the [Accessibility Documentation](ACCESSIBILITY.md).

## Responsive Design

The application is fully responsive and works on all device sizes:

- **Desktop**: 1025px and above
- **Tablet**: 769px to 1024px
- **Mobile**: 481px to 768px
- **Small Mobile**: 480px and below

For detailed information about responsive design implementation, see the [Responsive Design Documentation](RESPONSIVE_DESIGN.md).

## Development

### Backend Development

```bash
# Set up Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r backend/requirements.txt

# Run development server
cd backend
python app.py
```

### Frontend Development

```bash
# Install dependencies
cd frontend
npm install

# Run development server
npm start
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for providing the API
- [Flask](https://flask.palletsprojects.com/) for the backend framework
- [React](https://reactjs.org/) for the frontend framework
- [Docker](https://www.docker.com/) for containerization
- [PostgreSQL](https://www.postgresql.org/) for the database