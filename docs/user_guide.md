# VirusTotal File Scanner User Guide

Welcome to the VirusTotal File Scanner! This guide will help you understand how to use the application to scan files for malicious content using the VirusTotal service.

## Table of Contents

1. [Getting Started](#getting-started)
2. [API Key Management](#api-key-management)
3. [File Upload Process](#file-upload-process)
4. [Scan Results Interpretation](#scan-results-interpretation)
5. [Advanced Features](#advanced-features)
6. [Troubleshooting](#troubleshooting)

## Getting Started

### Creating an Account

1. Open the VirusTotal File Scanner application in your web browser.
2. Click on the "Register" button in the top-right corner.
3. Fill in the registration form with your username, email, and password.
4. Click "Register" to create your account.
5. You will be automatically logged in after successful registration.

### Logging In

1. Open the VirusTotal File Scanner application in your web browser.
2. Click on the "Login" button in the top-right corner.
3. Enter your username or email and password.
4. Click "Login" to access your account.

### Navigating the Interface

The application has a simple and intuitive interface with the following main sections:

- **Home**: Overview of the application and recent activity
- **Files**: List of your uploaded files
- **Scan Results**: View and manage scan results
- **API Keys**: Manage your VirusTotal API keys
- **Profile**: Update your user profile

## API Key Management

To use the VirusTotal File Scanner, you need to add at least one VirusTotal API key.

### Obtaining a VirusTotal API Key

1. Visit [VirusTotal](https://www.virustotal.com/) and create an account if you don't have one.
2. Log in to your VirusTotal account.
3. Navigate to your profile settings.
4. Find the API key section and copy your API key.

### Adding an API Key

1. In the VirusTotal File Scanner, navigate to the "API Keys" section.
2. Click the "Add API Key" button.
3. Enter a name for your API key (e.g., "My VirusTotal Key").
4. Paste your VirusTotal API key in the "Key Value" field.
5. Click "Save" to add the API key.

The application will validate your API key with VirusTotal before saving it. If the key is invalid, you will see an error message.

### Managing API Keys

In the "API Keys" section, you can:

- **View** your existing API keys (note that for security reasons, the actual key values are not displayed)
- **Edit** an API key's name by clicking the edit icon
- **Activate/Deactivate** an API key by toggling the active status
- **Delete** an API key by clicking the delete icon

### Setting a Default API Key

The first active API key will be used as the default for automatic scanning. To change the default:

1. Deactivate the current default API key.
2. Ensure the API key you want to use as default is active.

## File Upload Process

### Uploading Files

1. Navigate to the "Files" section or the home page.
2. Click the "Upload File" button or drag and drop files into the designated area.
3. Select one or more files from your computer.
4. The files will be uploaded and automatically queued for scanning if you have an active API key.

### File Upload Limitations

- Maximum file size: 50MB
- Allowed file types: Most common file formats (executables, documents, archives, etc.)
- Rate limiting: To prevent abuse, there are limits on how many files you can upload in a given time period

### Monitoring Upload Progress

During the upload process:

1. A progress bar will show the upload status for each file.
2. Once uploaded, the file will appear in your files list with a "Pending" or "Scanning" status.
3. You can click on a file to view its details and current scan status.

## Scan Results Interpretation

### Viewing Scan Results

1. Navigate to the "Scan Results" section or click on a specific file in the "Files" section.
2. Select a scan from the list to view detailed results.

### Understanding the Results

The scan results page shows:

- **File Information**: Name, size, upload date, and file hashes (MD5, SHA-1, SHA-256)
- **Detection Summary**: A ratio showing how many antivirus engines detected the file as malicious (e.g., "2/70" means 2 out of 70 engines detected issues)
- **Threat Categories**: Classification of any detected threats
- **Engine Results**: Detailed results from each antivirus engine

### Detection Categories

Scan results are categorized as follows:

- **Clean**: The file is considered safe by the antivirus engine
- **Malicious**: The file contains known malware or other malicious content
- **Suspicious**: The file has characteristics that might indicate malicious intent but isn't confirmed as malicious
- **Unknown**: The engine couldn't determine if the file is safe or malicious
- **Timeout**: The scan timed out before completion

### Interpreting Detection Ratios

The detection ratio (e.g., "2/70") indicates how many antivirus engines flagged the file as malicious:

- **0 detections**: The file is likely safe
- **1-3 detections**: Possibly a false positive, but exercise caution
- **4-10 detections**: Moderate risk, investigate further
- **11+ detections**: High risk, the file is likely malicious

### Rescanning Files

If you want to rescan a previously scanned file:

1. Navigate to the file details page.
2. Click the "Rescan" button.
3. The file will be submitted to VirusTotal for a fresh analysis.
4. Wait for the scan to complete and view the updated results.

## Advanced Features

### Filtering and Sorting Scan Results

In the "Scan Results" section, you can:

- **Filter** results by:
  - Detection ratio (minimum/maximum)
  - Scan date range
  - Scan status (completed, failed, pending, scanning)
- **Sort** results by:
  - Scan date (newest/oldest)
  - Detection ratio (highest/lowest)

### Exporting Results

To export scan results:

1. Navigate to a specific scan result.
2. Click the "Export" button.
3. Choose your preferred format (JSON, CSV, or PDF).
4. The file will be downloaded to your computer.

### Managing Files

In the "Files" section, you can:

- **Delete** files you no longer need
- **View file details** including all previous scans
- **Download** the original file (if needed for further analysis)

## Troubleshooting

### Common Issues

#### API Key Validation Fails

- Verify that your VirusTotal API key is correct
- Check if you've reached the API usage limits for your VirusTotal account
- Ensure your internet connection is stable

#### File Upload Fails

- Check if the file size exceeds the 50MB limit
- Verify that the file type is supported
- Ensure you have a stable internet connection

#### Scan Remains in "Scanning" Status

- VirusTotal processing can take time for large or complex files
- Check your internet connection
- Try refreshing the page or returning later

#### Missing Scan Results

- Ensure the scan has completed (status should be "Completed")
- Check if there were any errors during the scanning process
- Try rescanning the file

### Getting Help

If you encounter issues not covered in this guide:

1. Check the application's FAQ section
2. Contact the system administrator
3. Submit a support ticket through the application's help system