"""
Tests for the security measures implemented in the application.
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
from flask import url_for
from backend.utils.security import (
    sanitize_input, sanitize_dict, validate_uuid, 
    rate_limit, validate_content_type, secure_headers
)

def test_sanitize_input():
    """Test input sanitization function."""
    # Test basic sanitization
    assert sanitize_input('<script>alert("XSS")</script>') == '&lt;script&gt;alert("XSS")&lt;/script&gt;'
    
    # Test dangerous URL schemes
    assert 'javascript:' not in sanitize_input('javascript:alert(1)')
    assert 'data:' not in sanitize_input('data:text/html,<script>alert(1)</script>')
    
    # Test non-string input
    assert sanitize_input(123) == 123
    assert sanitize_input(None) is None

def test_sanitize_dict():
    """Test dictionary sanitization function."""
    # Test nested dictionary sanitization
    test_dict = {
        'name': '<script>alert("XSS")</script>',
        'nested': {
            'value': 'javascript:alert(1)'
        },
        'list': ['<img src="x" onerror="alert(1)">', 'normal text'],
        'number': 123
    }
    
    sanitized = sanitize_dict(test_dict)
    
    assert sanitized['name'] == '&lt;script&gt;alert("XSS")&lt;/script&gt;'
    assert 'javascript:' not in sanitized['nested']['value']
    assert sanitized['list'][0] == '&lt;img src="x" onerror="alert(1)"&gt;'
    assert sanitized['list'][1] == 'normal text'
    assert sanitized['number'] == 123
    
    # Test non-dict input
    assert sanitize_dict('string') == 'string'
    assert sanitize_dict(None) is None

def test_validate_uuid():
    """Test UUID validation function."""
    # Valid UUIDs
    assert validate_uuid('123e4567-e89b-12d3-a456-426614174000') is True
    assert validate_uuid('A23E4567-E89B-12D3-A456-426614174000') is True
    
    # Invalid UUIDs
    assert validate_uuid('not-a-uuid') is False
    assert validate_uuid('123e4567-e89b-12d3-a456') is False
    assert validate_uuid('123e4567-e89b-12d3-a456-4266141740001') is False
    assert validate_uuid(None) is False
    assert validate_uuid(123) is False

@pytest.mark.usefixtures('client_class', 'auth_tokens')
class TestSecurityMeasures:
    """Test the security measures implemented in the API endpoints."""
    
    def test_rate_limiting(self):
        """Test rate limiting on API endpoints."""
        # Make multiple requests to a rate-limited endpoint
        endpoint = '/api/files/'
        
        # First request should succeed
        response = self.client.get(
            endpoint,
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        assert response.status_code == 200
        
        # Check for rate limit headers
        assert 'X-RateLimit-Limit' in response.headers
        assert 'X-RateLimit-Remaining' in response.headers
        assert 'X-RateLimit-Reset' in response.headers
        
        # We can't easily test the actual rate limiting without making many requests
        # which would slow down the tests, so we'll just check that the headers are present
    
    def test_uuid_validation(self):
        """Test UUID validation on API endpoints."""
        # Test with invalid UUID
        invalid_uuid = 'not-a-uuid'
        
        # Test file endpoint
        response = self.client.get(
            f'/api/files/{invalid_uuid}',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid file ID format' in data.get('error', '')
        
        # Test scan endpoint
        response = self.client.get(
            f'/api/scan/{invalid_uuid}/status',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid scan ID format' in data.get('error', '')
    
    def test_content_type_validation(self):
        """Test Content-Type validation on API endpoints."""
        # Test with incorrect Content-Type
        response = self.client.post(
            '/api/scan/file/123e4567-e89b-12d3-a456-426614174000',
            headers={
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'text/plain'
            },
            data='This is not JSON'
        )
        assert response.status_code == 415
        data = json.loads(response.data)
        assert 'Invalid Content-Type' in data.get('error', '')
    
    def test_security_headers(self):
        """Test security headers are added to responses."""
        # Make a request to any endpoint
        response = self.client.get(
            '/health'
        )
        
        # Check for security headers
        assert 'Content-Security-Policy' in response.headers
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-XSS-Protection' in response.headers
        assert 'Strict-Transport-Security' in response.headers
        assert 'Referrer-Policy' in response.headers
    
    def test_error_handling(self):
        """Test global error handling."""
        # Test 404 error
        response = self.client.get('/non-existent-endpoint')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'Resource not found' in data.get('error', '')
        
        # Test 405 error
        response = self.client.post('/health')
        assert response.status_code == 405
        data = json.loads(response.data)
        assert 'Method not allowed' in data.get('error', '')