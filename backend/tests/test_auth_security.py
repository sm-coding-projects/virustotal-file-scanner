"""
Security-focused tests for the authentication system.
"""
import json
import time
import pytest
from flask_jwt_extended import decode_token
from unittest.mock import patch

def test_password_strength(client):
    """Test password strength requirements."""
    # Test with weak password (too short)
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'weakpassuser',
            'email': 'weak@example.com',
            'password': 'weak'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'password' in data['error'].lower()
    
    # Test with weak password (no complexity)
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'weakpassuser',
            'email': 'weak@example.com',
            'password': '12345678'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'password' in data['error'].lower()
    
    # Test with strong password
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'strongpassuser',
            'email': 'strong@example.com',
            'password': 'StrongP@ss123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 201

def test_brute_force_protection(client):
    """Test protection against brute force attacks."""
    # Create a test user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'bruteforceuser',
            'email': 'bruteforce@example.com',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    # Attempt multiple failed logins
    for i in range(5):
        response = client.post(
            '/api/auth/login',
            data=json.dumps({
                'username': 'bruteforceuser',
                'password': f'wrong_password_{i}'
            }),
            content_type='application/json'
        )
        assert response.status_code == 401
    
    # Check if rate limiting kicks in
    response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'bruteforceuser',
            'password': 'another_wrong_password'
        }),
        content_type='application/json'
    )
    
    # Should be rate limited after multiple failed attempts
    assert response.status_code == 429
    data = json.loads(response.data)
    assert 'error' in data
    assert 'rate limit' in data['error'].lower()

def test_token_security(client, app):
    """Test JWT token security features."""
    # Create a test user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'tokentestuser',
            'email': 'token@example.com',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    # Login to get tokens
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'tokentestuser',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    login_data = json.loads(login_response.data)
    access_token = login_data['access_token']
    refresh_token = login_data['refresh_token']
    
    # Decode tokens to check claims
    with app.app_context():
        access_claims = decode_token(access_token)
        refresh_claims = decode_token(refresh_token)
        
        # Check token types
        assert access_claims['type'] == 'access'
        assert refresh_claims['type'] == 'refresh'
        
        # Check expiration times
        assert 'exp' in access_claims
        assert 'exp' in refresh_claims
        assert access_claims['exp'] < refresh_claims['exp']
        
        # Check that tokens have appropriate expiration times
        # Access token should expire in less than a day
        assert access_claims['exp'] - time.time() < 86400
        
        # Check user identity
        assert 'sub' in access_claims
        assert 'sub' in refresh_claims
        assert access_claims['sub'] == refresh_claims['sub']

def test_session_invalidation(client):
    """Test session invalidation on logout."""
    # Create a test user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'logoutuser',
            'email': 'logout@example.com',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    # Login to get tokens
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'logoutuser',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    login_data = json.loads(login_response.data)
    access_token = login_data['access_token']
    
    # Use token to access protected endpoint
    profile_response = client.get(
        '/api/auth/profile',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    assert profile_response.status_code == 200
    
    # Logout
    logout_response = client.post(
        '/api/auth/logout',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    assert logout_response.status_code == 200
    
    # Try to use the same token after logout
    profile_response = client.get(
        '/api/auth/profile',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    assert profile_response.status_code == 401

def test_csrf_protection(client):
    """Test CSRF protection."""
    # Create a test user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'csrfuser',
            'email': 'csrf@example.com',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    # Login to get tokens
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'csrfuser',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    login_data = json.loads(login_response.data)
    access_token = login_data['access_token']
    
    # Check that CSRF protection headers are present
    assert 'X-CSRF-Token' in login_response.headers
    
    # Attempt to make a state-changing request without CSRF token
    response = client.post(
        '/api/auth/change-password',
        data=json.dumps({
            'current_password': 'SecureP@ss123',
            'new_password': 'NewSecureP@ss123'
        }),
        content_type='application/json',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    # Should be rejected due to missing CSRF token
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'csrf' in data['error'].lower()

def test_xss_protection_in_auth(client):
    """Test XSS protection in authentication endpoints."""
    # Try to register with XSS payload in username
    xss_payload = '<script>alert("XSS")</script>'
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': xss_payload,
            'email': 'xss@example.com',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    # Should succeed but sanitize the input
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['user']['username'] != xss_payload
    assert '<script>' not in data['user']['username']
    
    # Login with the sanitized username
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': data['user']['username'],
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    assert login_response.status_code == 200