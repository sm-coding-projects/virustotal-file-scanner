"""
Tests for file upload and management functionality.
"""
import os
import io
import json
import pytest
from flask_jwt_extended import create_access_token
from backend.models.database import User, File

@pytest.fixture
def auth_headers(app, test_user):
    """Create authentication headers for test user."""
    with app.app_context():
        access_token = create_access_token(identity=str(test_user.id))
        return {'Authorization': f'Bearer {access_token}'}

def test_upload_file_success(client, auth_headers, app):
    """Test successful file upload."""
    # Create test file
    data = {}
    data['file'] = (io.BytesIO(b'test file content'), 'test.txt')
    
    # Send request
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    # Check response
    assert response.status_code == 201
    response_data = json.loads(response.data)
    assert 'id' in response_data
    assert response_data['filename'] == 'test.txt'
    assert response_data['mime_type'] == 'text/plain'
    assert 'hash_md5' in response_data
    assert 'hash_sha1' in response_data
    assert 'hash_sha256' in response_data
    
    # Check database
    with app.app_context():
        file = File.query.filter_by(id=response_data['id']).first()
        assert file is not None
        assert file.filename == 'test.txt'
        
        # Clean up
        if os.path.exists(file.storage_path):
            os.remove(file.storage_path)
            # Try to remove parent directory
            parent_dir = os.path.dirname(file.storage_path)
            if os.path.exists(parent_dir) and not os.listdir(parent_dir):
                os.rmdir(parent_dir)

def test_upload_file_no_file(client, auth_headers):
    """Test file upload with no file."""
    response = client.post(
        '/api/files/upload',
        data={},
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'No file part' in response_data['error']

def test_upload_file_empty_filename(client, auth_headers):
    """Test file upload with empty filename."""
    data = {}
    data['file'] = (io.BytesIO(b''), '')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'No selected file' in response_data['error']

def test_upload_file_invalid_extension(client, auth_headers):
    """Test file upload with invalid extension."""
    data = {}
    data['file'] = (io.BytesIO(b'test content'), 'test.invalid')
    
    response = client.post(
        '/api/files/upload',
        data=data,
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 400
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'File type not allowed' in response_data['error']

def test_get_files(client, auth_headers, app, test_user):
    """Test getting list of files."""
    # Create a test file in the database
    with app.app_context():
        file = File(
            user_id=test_user.id,
            filename='test.txt',
            file_size=100,
            mime_type='text/plain',
            storage_path='/tmp/test.txt',
            hash_md5='d41d8cd98f00b204e9800998ecf8427e',
            hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
            hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        app.db.session.add(file)
        app.db.session.commit()
        file_id = str(file.id)
    
    # Send request
    response = client.get(
        '/api/files/',
        headers=auth_headers
    )
    
    # Check response
    assert response.status_code == 200
    response_data = json.loads(response.data)
    assert isinstance(response_data, list)
    assert len(response_data) >= 1
    
    # Find our test file in the response
    found = False
    for file_data in response_data:
        if file_data['id'] == file_id:
            found = True
            assert file_data['filename'] == 'test.txt'
            assert file_data['file_size'] == 100
            assert file_data['mime_type'] == 'text/plain'
            break
    
    assert found, "Test file not found in response"

def test_get_file(client, auth_headers, app, test_user):
    """Test getting a specific file."""
    # Create a test file in the database
    with app.app_context():
        file = File(
            user_id=test_user.id,
            filename='test.txt',
            file_size=100,
            mime_type='text/plain',
            storage_path='/tmp/test.txt',
            hash_md5='d41d8cd98f00b204e9800998ecf8427e',
            hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
            hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        app.db.session.add(file)
        app.db.session.commit()
        file_id = str(file.id)
    
    # Send request
    response = client.get(
        f'/api/files/{file_id}',
        headers=auth_headers
    )
    
    # Check response
    assert response.status_code == 200
    response_data = json.loads(response.data)
    assert response_data['id'] == file_id
    assert response_data['filename'] == 'test.txt'
    assert response_data['file_size'] == 100
    assert response_data['mime_type'] == 'text/plain'
    assert response_data['hash_md5'] == 'd41d8cd98f00b204e9800998ecf8427e'
    assert response_data['hash_sha1'] == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    assert response_data['hash_sha256'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

def test_get_file_not_found(client, auth_headers):
    """Test getting a non-existent file."""
    response = client.get(
        '/api/files/00000000-0000-0000-0000-000000000000',
        headers=auth_headers
    )
    
    assert response.status_code == 404
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'not found' in response_data['error']

def test_delete_file(client, auth_headers, app, test_user):
    """Test deleting a file."""
    # Create a test file in the database
    with app.app_context():
        # Create a temporary file
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_delete.txt')
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        with open(temp_path, 'w') as f:
            f.write('test content')
        
        file = File(
            user_id=test_user.id,
            filename='test_delete.txt',
            file_size=100,
            mime_type='text/plain',
            storage_path=temp_path,
            hash_md5='d41d8cd98f00b204e9800998ecf8427e',
            hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
            hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        app.db.session.add(file)
        app.db.session.commit()
        file_id = str(file.id)
    
    # Send request
    response = client.delete(
        f'/api/files/{file_id}',
        headers=auth_headers
    )
    
    # Check response
    assert response.status_code == 200
    response_data = json.loads(response.data)
    assert 'message' in response_data
    assert 'deleted successfully' in response_data['message']
    
    # Check database
    with app.app_context():
        file = File.query.filter_by(id=file_id).first()
        assert file is None
    
    # Check file system
    assert not os.path.exists(temp_path)

def test_delete_file_not_found(client, auth_headers):
    """Test deleting a non-existent file."""
    response = client.delete(
        '/api/files/00000000-0000-0000-0000-000000000000',
        headers=auth_headers
    )
    
    assert response.status_code == 404
    response_data = json.loads(response.data)
    assert 'error' in response_data
    assert 'not found' in response_data['error']