"""
Additional tests for the VirusTotal service.
"""
import os
import pytest
import re
from unittest.mock import patch, MagicMock
from backend.services.virustotal import VirusTotalService

def test_get_headers():
    """Test the _get_headers method."""
    with patch('backend.services.virustotal.current_app') as mock_app:
        mock_app.config = {'VIRUSTOTAL_API_URL': 'https://www.virustotal.com/api/v3'}
        
        # Test with instance API key
        service = VirusTotalService(api_key='test-api-key')
        headers = service._get_headers()
        
        assert headers['x-apikey'] == 'test-api-key'
        assert headers['accept'] == 'application/json'
        
        # Test with provided API key
        headers = service._get_headers(api_key='provided-api-key')
        assert headers['x-apikey'] == 'provided-api-key'

def test_get_file_report_by_hash():
    """Test getting a file report by hash."""
    with patch('backend.services.virustotal.current_app') as mock_app:
        mock_app.config = {'VIRUSTOTAL_API_URL': 'https://www.virustotal.com/api/v3'}
        
        service = VirusTotalService(api_key='test-api-key')
        
        # Test with no API key
        service.api_key = None
        success, error, data = service.get_file_report_by_hash('a' * 32)
        assert success is False
        assert error == "No API key provided"
        assert data is None
        
        # Reset API key
        service.api_key = 'test-api-key'
        
        # Test with invalid hash format
        success, error, data = service.get_file_report_by_hash('invalid-hash')
        assert success is False
        assert "Invalid file hash format" in error
        assert data is None
        
        # Test with valid MD5 hash
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'data': {'attributes': {'last_analysis_results': {}}}}
            mock_get.return_value = mock_response
            
            success, error, data = service.get_file_report_by_hash('a' * 32)
            assert success is True
            assert error is None
            assert data is not None
            assert 'data' in data
            
            # Verify the URL
            mock_get.assert_called_once()
            call_args = mock_get.call_args[0][0]
            assert call_args == 'https://www.virustotal.com/api/v3/files/' + 'a' * 32
        
        # Test with 404 response
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response
            
            success, error, data = service.get_file_report_by_hash('a' * 32)
            assert success is False
            assert error == "File not found in VirusTotal database"
            assert data is None
        
        # Test with connection error
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception("Connection error")
            
            success, error, data = service.get_file_report_by_hash('a' * 32)
            assert success is False
            assert "Connection error" in error
            assert data is None

def test_rescan_file():
    """Test requesting a rescan of a file."""
    with patch('backend.services.virustotal.current_app') as mock_app:
        mock_app.config = {'VIRUSTOTAL_API_URL': 'https://www.virustotal.com/api/v3'}
        
        service = VirusTotalService(api_key='test-api-key')
        
        # Test with no API key
        service.api_key = None
        success, error, data = service.rescan_file('a' * 32)
        assert success is False
        assert error == "No API key provided"
        assert data is None
        
        # Reset API key
        service.api_key = 'test-api-key'
        
        # Test with invalid hash format
        success, error, data = service.rescan_file('invalid-hash')
        assert success is False
        assert "Invalid file hash format" in error
        assert data is None
        
        # Test with valid MD5 hash
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'data': {'id': 'analysis-id', 'type': 'analysis'}}
            mock_post.return_value = mock_response
            
            success, error, data = service.rescan_file('a' * 32)
            assert success is True
            assert error is None
            assert data is not None
            assert 'data' in data
            
            # Verify the URL
            mock_post.assert_called_once()
            call_args = mock_post.call_args[0][0]
            assert call_args == 'https://www.virustotal.com/api/v3/files/' + 'a' * 32 + '/analyse'
        
        # Test with 404 response
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_post.return_value = mock_response
            
            success, error, data = service.rescan_file('a' * 32)
            assert success is False
            assert error == "File not found in VirusTotal database"
            assert data is None
        
        # Test with connection error
        with patch('requests.post') as mock_post:
            mock_post.side_effect = Exception("Connection error")
            
            success, error, data = service.rescan_file('a' * 32)
            assert success is False
            assert "Connection error" in error
            assert data is None

def test_parse_scan_results_error_handling():
    """Test error handling in parse_scan_results method."""
    with patch('backend.services.virustotal.current_app') as mock_app:
        mock_app.config = {'VIRUSTOTAL_API_URL': 'https://www.virustotal.com/api/v3'}
        mock_app.logger = MagicMock()
        
        service = VirusTotalService(api_key='test-api-key')
        
        # Test with invalid data structure
        result = service.parse_scan_results({'invalid': 'data'})
        assert result['status'] == 'error'
        assert 'error' in result
        assert result['detection_ratio'] == '0/0'
        assert result['engine_results'] == []
        
        # Test with None input
        result = service.parse_scan_results(None)
        assert result['status'] == 'error'
        assert 'error' in result
        
        # Test with empty stats
        result = service.parse_scan_results({
            'data': {
                'attributes': {
                    'status': 'completed',
                    'stats': {},
                    'results': {}
                }
            }
        })
        assert result['status'] == 'completed'
        assert result['detection_ratio'] == '0/0'
        assert result['engine_results'] == []
"""