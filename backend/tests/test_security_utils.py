"""
Additional tests for the security utilities.
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
from flask import Response
from backend.utils.security import (
    rate_limit, validate_content_type, security_headers_middleware
)

def test_rate_limit(app):
    """Test rate limiting decorator."""
    with app.test_request_context('/test'):
        # Create a test function with rate limiting
        @rate_limit(requests_per_minute=2)
        def test_function():
            return "OK"
        
        # First request should succeed
        response = test_function()
        assert isinstance(response, tuple)
        assert response[0] == "OK"
        assert response[1] == 200
        assert 'X-RateLimit-Limit' in response[2]
        assert response[2]['X-RateLimit-Limit'] == '2'
        assert response[2]['X-RateLimit-Remaining'] == '1'
        
        # Second request should succeed
        response = test_function()
        assert response[0] == "OK"
        assert response[1] == 200
        assert response[2]['X-RateLimit-Remaining'] == '0'
        
        # Third request should fail with 429 Too Many Requests
        response = test_function()
        assert response[1] == 429
        data = json.loads(response[0].data)
        assert 'error' in data
        assert 'Rate limit exceeded' in data['error']
        assert 'retry_after' in data

def test_validate_content_type(app):
    """Test content type validation decorator."""
    with app.test_request_context('/test', method='POST', 
                                 data=json.dumps({'test': 'data'}),
                                 content_type='application/json'):
        # Create a test function with content type validation
        @validate_content_type('application/json')
        def test_function():
            return "OK"
        
        # Request with correct content type should succeed
        response = test_function()
        assert response == "OK"
    
    with app.test_request_context('/test', method='POST', 
                                 data="<xml></xml>",
                                 content_type='application/xml'):
        # Request with incorrect content type should fail
        response = test_function()
        assert isinstance(response, tuple)
        assert response[1] == 415
        data = json.loads(response[0].data)
        assert 'error' in data
        assert 'Invalid Content-Type header' in data['error']

def test_security_headers_middleware(app):
    """Test security headers middleware."""
    # Create a mock response
    response = Response("Test")
    
    # Apply the middleware
    middleware = security_headers_middleware()
    result = middleware(response)
    
    # Check that headers were added
    assert 'Content-Security-Policy' in result.headers
    assert 'X-Content-Type-Options' in result.headers
    assert 'X-Frame-Options' in result.headers
    assert result.headers['X-Frame-Options'] == 'DENY'

def test_rate_limit_with_tuple_response(app):
    """Test rate limiting decorator with tuple response."""
    with app.test_request_context('/test'):
        # Create a test function with rate limiting that returns a tuple
        @rate_limit(requests_per_minute=2)
        def test_function():
            return "OK", 201, {'Custom-Header': 'Value'}
        
        # Request should succeed and preserve the tuple structure
        response = test_function()
        assert isinstance(response, tuple)
        assert len(response) == 3
        assert response[0] == "OK"
        assert response[1] == 201
        assert 'Custom-Header' in response[2]
        assert response[2]['Custom-Header'] == 'Value'
        assert 'X-RateLimit-Limit' in response[2]
        assert response[2]['X-RateLimit-Limit'] == '2'
"""