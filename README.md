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

Instructions for setting up and running the application will be provided here.

## License

This project is licensed under the MIT License - see the LICENSE file for details.