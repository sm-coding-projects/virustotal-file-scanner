# VirusTotal File Scanner API Documentation

This document provides detailed information about the VirusTotal File Scanner API endpoints, including request/response examples.

## Table of Contents

1. [Authentication](#authentication)
2. [API Key Management](#api-key-management)
3. [File Management](#file-management)
4. [Scan Management](#scan-management)

## Authentication

Authentication is handled using JSON Web Tokens (JWT). All protected endpoints require a valid JWT token in the Authorization header.

### Register a New User

**Endpoint:** `POST /api/auth/register`

**Description:** Register a new user account.

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john.doe@example.com",
  "password": "securePassword123"
}
```

**Response (201 Created):**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "johndoe",
    "email": "john.doe@example.com"
  }
}
```

**Error Responses:**
- 400 Bad Request: Missing required fields or invalid data
- 409 Conflict: Username or email already exists
- 500 Internal Server Error: Server error during registration

### Login

**Endpoint:** `POST /api/auth/login`

**Description:** Authenticate a user and receive JWT tokens.

**Request Body:**
```json
{
  "username": "johndoe",
  "password": "securePassword123"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "johndoe",
    "email": "john.doe@example.com"
  }
}
```

**Error Responses:**
- 400 Bad Request: Missing required fields
- 401 Unauthorized: Invalid username or password
- 500 Internal Server Error: Server error during login

### Refresh Token

**Endpoint:** `POST /api/auth/refresh`

**Description:** Get a new access token using a refresh token.

**Headers:**
- Authorization: Bearer {refresh_token}

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Responses:**
- 401 Unauthorized: Invalid refresh token
- 500 Internal Server Error: Server error during token refresh

### Get User Profile

**Endpoint:** `GET /api/auth/profile`

**Description:** Get the current user's profile information.

**Headers:**
- Authorization: Bearer {access_token}

**Response (200 OK):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "johndoe",
    "email": "john.doe@example.com"
  }
}
```

**Error Responses:**
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: User not found
- 500 Internal Server Error: Server error

### Update User Profile

**Endpoint:** `PUT /api/auth/profile`

**Description:** Update the current user's profile information.

**Headers:**
- Authorization: Bearer {access_token}

**Request Body:**
```json
{
  "username": "johndoe_updated",
  "email": "john.updated@example.com",
  "current_password": "securePassword123",
  "new_password": "newSecurePassword456"
}
```

**Response (200 OK):**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "johndoe_updated",
    "email": "john.updated@example.com"
  }
}
```

**Error Responses:**
- 400 Bad Request: Invalid data
- 401 Unauthorized: Invalid or expired token, or incorrect current password
- 409 Conflict: Username or email already exists
- 500 Internal Server Error: Server error during update

### Logout

**Endpoint:** `POST /api/auth/logout`

**Description:** Logout the current user. Note that JWT tokens are stateless, so this endpoint doesn't actually invalidate the token. The client should discard the token.

**Headers:**
- Authorization: Bearer {access_token}

**Response (200 OK):**
```json
{
  "message": "Successfully logged out"
}
```

**Error Responses:**
- 401 Unauthorized: Invalid or expired token
- 500 Internal Server Error: Server error during logout

## API Key Management

These endpoints allow users to manage their VirusTotal API keys.

### Get All API Keys

**Endpoint:** `GET /api/keys/`

**Description:** Get all API keys for the current user.

**Headers:**
- Authorization: Bearer {access_token}

**Response (200 OK):**
```json
{
  "api_keys": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "My VirusTotal API Key",
      "is_active": true,
      "created_at": "2023-01-01T12:00:00.000Z",
      "updated_at": "2023-01-01T12:00:00.000Z"
    }
  ]
}
```

**Error Responses:**
- 401 Unauthorized: Invalid or expired token
- 500 Internal Server Error: Server error

### Create API Key

**Endpoint:** `POST /api/keys/`

**Description:** Create a new API key.

**Headers:**
- Authorization: Bearer {access_token}

**Request Body:**
```json
{
  "name": "My VirusTotal API Key",
  "key_value": "your_virustotal_api_key_here"
}
```

**Response (201 Created):**
```json
{
  "message": "API key created successfully",
  "api_key": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "My VirusTotal API Key",
    "is_active": true,
    "created_at": "2023-01-01T12:00:00.000Z",
    "updated_at": "2023-01-01T12:00:00.000Z"
  }
}
```

**Error Responses:**
- 400 Bad Request: Missing required fields or invalid API key
- 401 Unauthorized: Invalid or expired token
- 500 Internal Server Error: Server error during creation

### Get API Key

**Endpoint:** `GET /api/keys/{key_id}`

**Description:** Get a specific API key.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- key_id: UUID of the API key

**Response (200 OK):**
```json
{
  "api_key": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "My VirusTotal API Key",
    "is_active": true,
    "created_at": "2023-01-01T12:00:00.000Z",
    "updated_at": "2023-01-01T12:00:00.000Z"
  }
}
```

**Error Responses:**
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: API key not found
- 500 Internal Server Error: Server error

### Update API Key

**Endpoint:** `PUT /api/keys/{key_id}`

**Description:** Update an API key.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- key_id: UUID of the API key

**Request Body:**
```json
{
  "name": "Updated API Key Name",
  "key_value": "new_virustotal_api_key_here",
  "is_active": false
}
```

**Response (200 OK):**
```json
{
  "message": "API key updated successfully",
  "api_key": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Updated API Key Name",
    "is_active": false,
    "created_at": "2023-01-01T12:00:00.000Z",
    "updated_at": "2023-01-01T12:30:00.000Z"
  }
}
```

**Error Responses:**
- 400 Bad Request: No update data provided or invalid API key
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: API key not found
- 500 Internal Server Error: Server error during update

### Delete API Key

**Endpoint:** `DELETE /api/keys/{key_id}`

**Description:** Delete an API key.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- key_id: UUID of the API key

**Response (200 OK):**
```json
{
  "message": "API key deleted successfully"
}
```

**Error Responses:**
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: API key not found
- 500 Internal Server Error: Server error during deletion

### Validate API Key

**Endpoint:** `POST /api/keys/validate`

**Description:** Validate an API key with VirusTotal.

**Headers:**
- Authorization: Bearer {access_token}

**Request Body:**
```json
{
  "key_value": "virustotal_api_key_to_validate"
}
```

**Response (200 OK):**
```json
{
  "valid": true,
  "message": "API key is valid"
}
```

**Error Responses:**
- 400 Bad Request: API key is required
- 401 Unauthorized: Invalid or expired token
- 500 Internal Server Error: Server error during validation

## File Management

These endpoints allow users to manage files for scanning.

### Upload File

**Endpoint:** `POST /api/files/upload`

**Description:** Upload a file for scanning.

**Headers:**
- Authorization: Bearer {access_token}
- Content-Type: multipart/form-data

**Form Data:**
- file: The file to upload

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "test_file.txt",
  "file_size": 1024,
  "mime_type": "text/plain",
  "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
  "hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "upload_date": "2023-01-01T12:00:00.000Z",
  "scan": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440001",
    "status": "scanning",
    "message": "Scan initiated automatically"
  }
}
```

**Error Responses:**
- 400 Bad Request: No file part, no selected file, file type not allowed, or file too large
- 401 Unauthorized: Invalid or expired token
- 500 Internal Server Error: Server error during upload

### Get All Files

**Endpoint:** `GET /api/files/`

**Description:** Get a list of files uploaded by the current user.

**Headers:**
- Authorization: Bearer {access_token}

**Response (200 OK):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "filename": "test_file.txt",
    "file_size": 1024,
    "mime_type": "text/plain",
    "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
    "hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "upload_date": "2023-01-01T12:00:00.000Z"
  }
]
```

**Error Responses:**
- 401 Unauthorized: Invalid or expired token
- 500 Internal Server Error: Server error

### Get File

**Endpoint:** `GET /api/files/{file_id}`

**Description:** Get information about a specific file.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- file_id: UUID of the file

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "test_file.txt",
  "file_size": 1024,
  "mime_type": "text/plain",
  "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
  "hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "upload_date": "2023-01-01T12:00:00.000Z"
}
```

**Error Responses:**
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: File not found
- 500 Internal Server Error: Server error

### Delete File

**Endpoint:** `DELETE /api/files/{file_id}`

**Description:** Delete a file.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- file_id: UUID of the file

**Response (200 OK):**
```json
{
  "message": "File deleted successfully"
}
```

**Error Responses:**
- 400 Bad Request: Invalid file ID format
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: File not found
- 500 Internal Server Error: Server error during deletion

## Scan Management

These endpoints allow users to manage file scans.

### Scan File

**Endpoint:** `POST /api/scan/file/{file_id}`

**Description:** Scan a file using VirusTotal API.

**Headers:**
- Authorization: Bearer {access_token}
- Content-Type: application/json

**Parameters:**
- file_id: UUID of the file to scan

**Request Body (optional):**
```json
{
  "api_key_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (202 Accepted):**
```json
{
  "message": "Scan initiated successfully",
  "scan_id": "550e8400-e29b-41d4-a716-446655440001",
  "status": "scanning"
}
```

**Error Responses:**
- 400 Bad Request: Invalid file ID format, no active API key found, or API key is not active
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: File not found or API key not found
- 500 Internal Server Error: Server error during scan

### Get Scan Status

**Endpoint:** `GET /api/scan/{scan_id}/status`

**Description:** Get the status of a scan.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- scan_id: UUID of the scan

**Response (200 OK):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440001",
  "status": "completed",
  "detection_ratio": "2/70",
  "scan_date": "2023-01-01T12:30:00.000Z"
}
```

**Error Responses:**
- 400 Bad Request: Invalid scan ID format
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: Scan not found
- 500 Internal Server Error: Server error

### Get Scan Results

**Endpoint:** `GET /api/scan/{scan_id}/results`

**Description:** Get the results of a scan.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- scan_id: UUID of the scan

**Response (200 OK):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440001",
  "file_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "test_file.txt",
  "status": "completed",
  "detection_ratio": "2/70",
  "scan_date": "2023-01-01T12:30:00.000Z",
  "results": [
    {
      "engine_name": "Engine1",
      "engine_version": "1.0.0",
      "result": "malicious",
      "category": "malware",
      "update_date": "2023-01-01T12:00:00.000Z"
    },
    {
      "engine_name": "Engine2",
      "engine_version": "2.0.0",
      "result": "clean",
      "category": "undetected",
      "update_date": "2023-01-01T12:00:00.000Z"
    }
  ],
  "summary": {
    "malicious": 2,
    "suspicious": 0,
    "undetected": 68,
    "timeout": 0,
    "detection_ratio": "2/70"
  }
}
```

**Error Responses:**
- 400 Bad Request: Invalid scan ID format
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: Scan not found or file not found
- 500 Internal Server Error: Server error

### Rescan File

**Endpoint:** `POST /api/scan/file/{file_id}/rescan`

**Description:** Rescan a previously scanned file.

**Headers:**
- Authorization: Bearer {access_token}
- Content-Type: application/json

**Parameters:**
- file_id: UUID of the file to rescan

**Request Body (optional):**
```json
{
  "api_key_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (202 Accepted):**
```json
{
  "message": "Rescan initiated successfully",
  "scan_id": "550e8400-e29b-41d4-a716-446655440002",
  "status": "scanning"
}
```

**Error Responses:**
- 400 Bad Request: Invalid file ID format, no active API key found, or API key is not active
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: File not found or API key not found
- 500 Internal Server Error: Server error during rescan

### Get All Scan Results

**Endpoint:** `GET /api/scan/results`

**Description:** Get all scan results with filtering and sorting options.

**Headers:**
- Authorization: Bearer {access_token}

**Query Parameters:**
- status: Filter by scan status (completed, failed, pending, scanning)
- detection_min: Filter by minimum detection ratio (e.g., 1)
- detection_max: Filter by maximum detection ratio (e.g., 10)
- date_from: Filter by scan date from (ISO format)
- date_to: Filter by scan date to (ISO format)
- sort_by: Field to sort by (scan_date, detection_ratio)
- sort_order: Sort order (asc, desc)
- page: Page number for pagination
- per_page: Number of results per page

**Response (200 OK):**
```json
{
  "scans": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "file_id": "550e8400-e29b-41d4-a716-446655440000",
      "filename": "test_file.txt",
      "status": "completed",
      "detection_ratio": "2/70",
      "scan_date": "2023-01-01T12:30:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total_pages": 1,
    "total_items": 1
  }
}
```

**Error Responses:**
- 400 Bad Request: Invalid filter parameters
- 401 Unauthorized: Invalid or expired token
- 500 Internal Server Error: Server error

### Export Scan Results

**Endpoint:** `GET /api/scan/{scan_id}/export`

**Description:** Export scan results in various formats.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- scan_id: UUID of the scan

**Query Parameters:**
- format: Export format (json, csv, pdf)

**Response (200 OK):**
- For JSON format: JSON file download
- For CSV format: CSV file download
- For PDF format: PDF file download

**Error Responses:**
- 400 Bad Request: Invalid scan ID format or unsupported format
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: Scan not found
- 500 Internal Server Error: Server error during export

### Get File Scans

**Endpoint:** `GET /api/scan/file/{file_id}`

**Description:** Get all scans for a file.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- file_id: UUID of the file

**Response (200 OK):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "status": "completed",
    "detection_ratio": "2/70",
    "scan_date": "2023-01-01T12:30:00.000Z"
  },
  {
    "id": "550e8400-e29b-41d4-a716-446655440002",
    "status": "completed",
    "detection_ratio": "3/70",
    "scan_date": "2023-01-02T12:30:00.000Z"
  }
]
```

**Error Responses:**
- 400 Bad Request: Invalid file ID format
- 401 Unauthorized: Invalid or expired token
- 404 Not Found: File not found
- 500 Internal Server Error: Server error

### Get User Scans

**Endpoint:** `GET /api/scan/user/{user_id}`

**Description:** Get all scans for a user.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- user_id: UUID of the user

**Response (200 OK):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "file_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "detection_ratio": "2/70",
    "scan_date": "2023-01-01T12:30:00.000Z"
  }
]
```

**Error Responses:**
- 400 Bad Request: Invalid user ID format
- 401 Unauthorized: Invalid or expired token
- 403 Forbidden: Unauthorized access to another user's scans
- 404 Not Found: User not found
- 500 Internal Server Error: Server error