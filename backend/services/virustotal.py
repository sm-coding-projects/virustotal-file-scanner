"""
VirusTotal API service for the VirusTotal File Scanner application.
"""
import os
import time
import requests
import re
from flask import current_app
from typing import Dict, Tuple, Optional, Any, List
from backend.utils.security import sanitize_dict

class VirusTotalService:
    """Service for interacting with the VirusTotal API."""
    
    def __init__(self, api_key=None):
        """
        Initialize the VirusTotal service.
        
        Args:
            api_key: VirusTotal API key (optional)
        """
        self.api_key = api_key
        self.base_url = current_app.config['VIRUSTOTAL_API_URL']
    
    def _get_headers(self, api_key=None) -> Dict[str, str]:
        """
        Get headers for VirusTotal API requests.
        
        Args:
            api_key: API key to use (uses instance key if not provided)
            
        Returns:
            Dictionary of headers
        """
        key = api_key or self.api_key
        return {
            'x-apikey': key,
            'accept': 'application/json'
        }
    
    def validate_api_key(self, api_key=None) -> Tuple[bool, Optional[str]]:
        """
        Validate a VirusTotal API key by making a test request.
        
        Args:
            api_key: API key to validate (uses instance key if not provided)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        key = api_key or self.api_key
        if not key:
            return False, "No API key provided"
        
        headers = self._get_headers(key)
        
        try:
            # Make a request to the user endpoint to validate the API key
            response = requests.get(f"{self.base_url}/users/current", headers=headers, timeout=10)
            
            if response.status_code == 200:
                # API key is valid
                return True, None
            elif response.status_code == 401:
                # API key is invalid
                return False, "Invalid API key"
            else:
                # Other error
                return False, f"API error: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Error validating VirusTotal API key: {str(e)}")
            return False, f"Connection error: {str(e)}"
    
    def scan_file(self, file_path: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Upload a file to VirusTotal for scanning.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Tuple of (success, error_message, scan_data)
        """
        if not self.api_key:
            return False, "No API key provided", None
        
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}", None
        
        headers = self._get_headers()
        
        try:
            # Open the file in binary mode
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                
                # Upload the file to VirusTotal
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=headers,
                    files=files,
                    timeout=60  # Longer timeout for file uploads
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # Sanitize the response data to prevent XSS and other injection attacks
                    sanitized_data = sanitize_dict(data)
                    return True, None, sanitized_data
                elif response.status_code == 401:
                    return False, "Invalid API key", None
                elif response.status_code == 413:
                    return False, "File too large for VirusTotal API", None
                else:
                    return False, f"API error: {response.status_code}", None
                    
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Error scanning file with VirusTotal: {str(e)}")
            return False, f"Connection error: {str(e)}", None
    
    def get_file_report_by_hash(self, file_hash: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Get a file report from VirusTotal using its hash.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of the file
            
        Returns:
            Tuple of (success, error_message, report_data)
        """
        if not self.api_key:
            return False, "No API key provided", None
        
        # Validate file hash format
        if not re.match(r'^[a-fA-F0-9]{32,64}$', file_hash):
            return False, "Invalid file hash format", None
        
        headers = self._get_headers()
        
        try:
            # Get the file report from VirusTotal
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                # Sanitize the response data to prevent XSS and other injection attacks
                sanitized_data = sanitize_dict(data)
                return True, None, sanitized_data
            elif response.status_code == 401:
                return False, "Invalid API key", None
            elif response.status_code == 404:
                return False, "File not found in VirusTotal database", None
            else:
                return False, f"API error: {response.status_code}", None
                
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Error getting file report from VirusTotal: {str(e)}")
            return False, f"Connection error: {str(e)}", None
    
    def get_analysis_status(self, analysis_id: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Get the status of a VirusTotal analysis.
        
        Args:
            analysis_id: ID of the analysis to check
            
        Returns:
            Tuple of (success, error_message, analysis_data)
        """
        if not self.api_key:
            return False, "No API key provided", None
        
        # Validate analysis ID format
        if not re.match(r'^[a-zA-Z0-9_-]+$', analysis_id):
            return False, "Invalid analysis ID format", None
        
        headers = self._get_headers()
        
        try:
            # Get the analysis status from VirusTotal
            response = requests.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                # Sanitize the response data to prevent XSS and other injection attacks
                sanitized_data = sanitize_dict(data)
                return True, None, sanitized_data
            elif response.status_code == 401:
                return False, "Invalid API key", None
            elif response.status_code == 404:
                return False, "Analysis not found", None
            else:
                return False, f"API error: {response.status_code}", None
                
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Error getting analysis status from VirusTotal: {str(e)}")
            return False, f"Connection error: {str(e)}", None
    
    def parse_scan_results(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse VirusTotal scan results into a structured format.
        
        Args:
            analysis_data: Raw analysis data from VirusTotal API
            
        Returns:
            Dictionary containing parsed scan results
        """
        try:
            # Sanitize input data
            sanitized_data = sanitize_dict(analysis_data)
            
            # Extract the analysis attributes
            attributes = sanitized_data.get('data', {}).get('attributes', {})
            stats = attributes.get('stats', {})
            results = attributes.get('results', {})
            status = attributes.get('status', 'unknown')
            
            # Calculate detection ratio
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
            
            # Extract engine results
            engine_results = []
            for engine_name, engine_data in results.items():
                engine_results.append({
                    'engine_name': engine_name,
                    'engine_version': engine_data.get('engine_version', ''),
                    'result': engine_data.get('result', ''),
                    'category': engine_data.get('category', ''),
                    'update_date': engine_data.get('engine_update', '')
                })
            
            # Create summary
            summary = {
                'status': status,
                'stats': stats,
                'detection_ratio': detection_ratio,
                'scan_date': attributes.get('date', ''),
                'engine_results': engine_results
            }
            
            return summary
            
        except Exception as e:
            current_app.logger.error(f"Error parsing VirusTotal scan results: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'detection_ratio': '0/0',
                'engine_results': []
            }
    
    def rescan_file(self, file_hash: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Request VirusTotal to rescan a previously submitted file.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of the file
            
        Returns:
            Tuple of (success, error_message, rescan_data)
        """
        if not self.api_key:
            return False, "No API key provided", None
        
        # Validate file hash format
        if not re.match(r'^[a-fA-F0-9]{32,64}$', file_hash):
            return False, "Invalid file hash format", None
        
        headers = self._get_headers()
        
        try:
            # Request a rescan from VirusTotal
            response = requests.post(
                f"{self.base_url}/files/{file_hash}/analyse",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                # Sanitize the response data to prevent XSS and other injection attacks
                sanitized_data = sanitize_dict(data)
                return True, None, sanitized_data
            elif response.status_code == 401:
                return False, "Invalid API key", None
            elif response.status_code == 404:
                return False, "File not found in VirusTotal database", None
            else:
                return False, f"API error: {response.status_code}", None
                
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Error requesting rescan from VirusTotal: {str(e)}")
            return False, f"Connection error: {str(e)}", None