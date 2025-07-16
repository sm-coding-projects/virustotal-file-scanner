"""
VirusTotal API service for the VirusTotal File Scanner application.
"""
import requests
from flask import current_app

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
    
    def validate_api_key(self, api_key=None):
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
        
        headers = {
            'x-apikey': key,
            'accept': 'application/json'
        }
        
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