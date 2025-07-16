"""
Tests for the authentication system.
"""
import json
import pytest
from flask_jwt_extended import decode_token
from backend.models.database import User

def test_register(client, app):
    """Test user registration."""
    # Test successful registration
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'user' in data
    assert data['user']['username'] == 'testuser'
    assert data['user']['email'] == 'test@example.com'
    
    # Test duplicate username
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'testuser',
            'email': 'another@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 409
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Username already exists' in data['error']
    
    # Test duplicate email
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'anotheruser',
            'email': 'test@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 409
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Email already exists' in data['error']
    
    # Test invalid data
    response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'ab',  # Too short
            'email': 'test@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_login(client, app):
    """Test user login."""
    # Create a test user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'loginuser',
            'email': 'login@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    # Test successful login with username
    response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'loginuser',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert 'user' in data
    assert data['user']['username'] == 'loginuser'
    
    # Test successful login with email
    response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'login@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    
    # Test invalid credentials
    response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'loginuser',
            'password': 'wrongpassword'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid username or password' in data['error']


def test_profile(client, app):
    """Test user profile endpoints."""
    # Create a test user
    register_response = client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'profileuser',
            'email': 'profile@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    # Login to get tokens
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'profileuser',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    login_data = json.loads(login_response.data)
    access_token = login_data['access_token']
    
    # Test get profile
    response = client.get(
        '/api/auth/profile',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'user' in data
    assert data['user']['username'] == 'profileuser'
    assert data['user']['email'] == 'profile@example.com'
    
    # Test update profile
    response = client.put(
        '/api/auth/profile',
        data=json.dumps({
            'username': 'updateduser'
        }),
        content_type='application/json',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'user' in data
    assert data['user']['username'] == 'updateduser'
    
    # Test update password
    response = client.put(
        '/api/auth/profile',
        data=json.dumps({
            'current_password': 'password123',
            'new_password': 'newpassword123'
        }),
        content_type='application/json',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    assert response.status_code == 200
    
    # Test login with new password
    response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'updateduser',
            'password': 'newpassword123'
        }),
        content_type='application/json'
    )
    
    assert response.status_code == 200


def test_refresh_token(client, app):
    """Test token refresh."""
    # Create a test user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'refreshuser',
            'email': 'refresh@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    # Login to get tokens
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'refreshuser',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    login_data = json.loads(login_response.data)
    refresh_token = login_data['refresh_token']
    
    # Test token refresh
    response = client.post(
        '/api/auth/refresh',
        headers={'Authorization': f'Bearer {refresh_token}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data


def test_logout(client, app):
    """Test user logout."""
    # Create a test user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'logoutuser',
            'email': 'logout@example.com',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    # Login to get tokens
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'logoutuser',
            'password': 'password123'
        }),
        content_type='application/json'
    )
    
    login_data = json.loads(login_response.data)
    access_token = login_data['access_token']
    
    # Test logout
    response = client.post(
        '/api/auth/logout',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'Successfully logged out' in data['message']