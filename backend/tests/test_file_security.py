"""
Security tests for file upload functionality.
"""
import os
import io
import json
import pytest
from unittest.mock import patch, MagicMock
from werkzeug.datastructures import FileStorage

def test_file_type_validation(client, auth_headers):
    """Test validation of file types to prevent malicious uploads."""
    # Test with allowed file type
    data = {}
    data['file'] = (io.BytesIO(b'test file content'), 'test.txt')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 201
    
    # Test with executable file
    data = {}
    data['file'] = (io.BytesIO(b'#!/bin/bash\necho "Malicious script"'), 'malicious.sh')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'file type' in response_data['error'].lower()
    
    # Test with disguised executable (wrong extension)
    data = {}
    data['file'] = (io.BytesIO(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00'), 'malicious.txt')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    # Should detect the mismatch between content and extension
    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert 'error' in response_data

def test_file_size_limits(client, auth_headers):
    """Test file size limits to prevent DoS attacks."""
    # Test with acceptable file size
    data = {}
    data['file'] = (io.BytesIO(b'small file content'), 'small.txt')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 201
    
    # Test with file exceeding size limit
    # Create a large file (101 MB)
    large_content = b'0' * (101 * 1024 * 1024)
    data = {}
    data['file'] = (io.BytesIO(large_content), 'large.txt')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'file size' in response_data['error'].lower()

def test_path_traversal_prevention(client, auth_headers, app):
    """Test prevention of path traversal attacks."""
    # Attempt path traversal in filename
    data = {}
    data['file'] = (io.BytesIO(b'path traversal attempt'), '../../../etc/passwd')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    # Should sanitize the filename
    assert response.status_code == 201
    response_data = json.loads(response.data)
    
    # Check that the file was stored with a sanitized name
    with app.app_context():
        from backend.models.database import File
        file = File.query.filter_by(id=response_data['id']).first()
        assert file is not None
        assert '../' not in file.storage_path
        assert 'etc/passwd' not in file.storage_path
        
        # Clean up
        if os.path.exists(file.storage_path):
            os.remove(file.storage_path)

def test_file_content_validation(client, auth_headers):
    """Test validation of file content to prevent malicious uploads."""
    # Test with benign text file
    data = {}
    data['file'] = (io.BytesIO(b'This is a normal text file'), 'normal.txt')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 201
    
    # Test with file containing potential XSS payload
    data = {}
    data['file'] = (io.BytesIO(b'<script>alert("XSS")</script>'), 'xss.html')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    # HTML files should be rejected or properly handled
    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert 'error' in response_data

def test_file_upload_rate_limiting(client, auth_headers):
    """Test rate limiting for file uploads to prevent DoS attacks."""
    # Make multiple rapid file uploads
    for i in range(10):
        data = {}
        data['file'] = (io.BytesIO(f'file content {i}'.encode()), f'file{i}.txt')
        
        response = client.post(
            '/api/files/upload',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        
        # Check if rate limiting kicks in after several uploads
        if response.status_code == 429:
            # Rate limiting detected
            response_data = json.loads(response.data)
            assert 'error' in response_data
            assert 'rate limit' in response_data['error'].lower()
            break
        
        # If we've made it through all uploads without rate limiting, check headers
        if i == 9:
            assert 'X-RateLimit-Remaining' in response.headers
            remaining = int(response.headers['X-RateLimit-Remaining'])
            assert remaining >= 0

def test_file_permissions(client, auth_headers, app):
    """Test that users can only access their own files."""
    # Create a file for the authenticated user
    data = {}
    data['file'] = (io.BytesIO(b'user1 file content'), 'user1_file.txt')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 201
    response_data = json.loads(response.data)
    file_id = response_data['id']
    
    # Create a second user
    client.post(
        '/api/auth/register',
        data=json.dumps({
            'username': 'user2',
            'email': 'user2@example.com',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    # Login as second user
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps({
            'username': 'user2',
            'password': 'SecureP@ss123'
        }),
        content_type='application/json'
    )
    
    login_data = json.loads(login_response.data)
    user2_token = login_data['access_token']
    user2_headers = {'Authorization': f'Bearer {user2_token}'}
    
    # Try to access first user's file as second user
    response = client.get(
        f'/api/files/{file_id}',
        headers=user2_headers
    )
    
    # Should be denied access
    assert response.status_code == 403
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'permission' in response_data['error'].lower()

def test_secure_file_deletion(client, auth_headers, app):
    """Test secure file deletion to prevent data leakage."""
    # Create a test file
    data = {}
    data['file'] = (io.BytesIO(b'sensitive content'), 'sensitive.txt')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 201
    response_data = json.loads(response.data)
    file_id = response_data['id']
    
    # Get the file path
    with app.app_context():
        from backend.models.database import File
        file = File.query.filter_by(id=file_id).first()
        file_path = file.storage_path
        
        # Ensure file exists
        assert os.path.exists(file_path)
    
    # Delete the file
    response = client.delete(
        f'/api/files/{file_id}',
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify file is deleted from filesystem
    assert not os.path.exists(file_path)
    
    # Verify file is deleted from database
    with app.app_context():
        from backend.models.database import File
        file = File.query.filter_by(id=file_id).first()
        assert file is None