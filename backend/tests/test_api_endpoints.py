"""
Tests for API endpoints.
"""
import json
import pytest
import uuid
from unittest.mock import patch, MagicMock
from flask_jwt_extended import create_access_token
from backend.models.database import db, User, ApiKey, File, Scan, ScanResult, ScanStatus

@pytest.fixture
def auth_tokens(app, test_user):
    """Create authentication tokens for test user."""
    with app.app_context():
        access_token = create_access_token(identity=str(test_user.id))
        refresh_token = create_access_token(identity=str(test_user.id), additional_claims={"refresh": True})
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

@pytest.mark.usefixtures('client_class')
class TestAuthAPI:
    """Test authentication API endpoints."""
    
    def test_register_validation(self):
        """Test user registration validation."""
        # Test with missing fields
        response = self.client.post(
            '/api/auth/register',
            json={
                'username': 'testuser'
                # Missing email and password
            }
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        
        # Test with invalid email
        response = self.client.post(
            '/api/auth/register',
            json={
                'username': 'testuser',
                'email': 'invalid-email',
                'password': 'password123'
            }
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        
        # Test with short password
        response = self.client.post(
            '/api/auth/register',
            json={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'short'  # Too short
            }
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_login_validation(self):
        """Test login validation."""
        # Test with missing fields
        response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'testuser'
                # Missing password
            }
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        
        # Test with non-existent user
        response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'nonexistentuser',
                'password': 'password123'
            }
        )
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data

@pytest.mark.usefixtures('client_class')
class TestFilesAPI:
    """Test files API endpoints."""
    
    def test_get_file_not_found(self, auth_tokens):
        """Test getting a non-existent file."""
        # Generate a random UUID that doesn't exist
        random_id = str(uuid.uuid4())
        
        response = self.client.get(
            f'/api/files/{random_id}',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'}
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_delete_file_unauthorized(self, app, test_user, auth_tokens):
        """Test deleting a file without authorization."""
        # Create another user
        with app.app_context():
            other_user = User(
                username='otheruser',
                email='other@example.com',
                password_hash='hashed_password'
            )
            db.session.add(other_user)
            db.session.commit()
            
            # Create a file owned by the other user
            file = File(
                user_id=other_user.id,
                filename='otheruser.txt',
                file_size=100,
                mime_type='text/plain',
                storage_path='/tmp/otheruser.txt',
                hash_md5='d41d8cd98f00b204e9800998ecf8427e',
                hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
                hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            )
            db.session.add(file)
            db.session.commit()
            file_id = str(file.id)
        
        # Try to delete the file as the test_user
        response = self.client.delete(
            f'/api/files/{file_id}',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'}
        )
        
        assert response.status_code == 403
        data = json.loads(response.data)
        assert 'error' in data
        assert 'permission' in data['error'].lower()

@pytest.mark.usefixtures('client_class')
class TestKeysAPI:
    """Test API keys endpoints."""
    
    def test_create_api_key_validation(self, auth_tokens):
        """Test API key creation validation."""
        # Test with missing fields
        response = self.client.post(
            '/api/keys/',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'},
            json={
                'name': 'Test Key'
                # Missing key_value
            }
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Missing required fields' in data['error']
        
        # Test with empty key value
        response = self.client.post(
            '/api/keys/',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'},
            json={
                'name': 'Test Key',
                'key_value': ''
            }
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    @patch('backend.services.virustotal.VirusTotalService.validate_api_key')
    def test_update_api_key_not_found(self, mock_validate, auth_tokens):
        """Test updating a non-existent API key."""
        # Mock the validation to return success
        mock_validate.return_value = (True, None)
        
        # Generate a random UUID that doesn't exist
        random_id = str(uuid.uuid4())
        
        response = self.client.put(
            f'/api/keys/{random_id}',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'},
            json={
                'name': 'Updated Key',
                'is_active': False
            }
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data

@pytest.mark.usefixtures('client_class')
class TestScanAPI:
    """Test scan API endpoints."""
    
    def test_scan_file_not_found(self, auth_tokens):
        """Test scanning a non-existent file."""
        # Generate a random UUID that doesn't exist
        random_id = str(uuid.uuid4())
        
        response = self.client.post(
            f'/api/scan/file/{random_id}',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'}
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_scan_file_no_api_key(self, app, test_user, auth_tokens):
        """Test scanning a file without an API key."""
        # Create a file
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
            db.session.add(file)
            db.session.commit()
            file_id = str(file.id)
        
        # Try to scan the file without having an API key
        response = self.client.post(
            f'/api/scan/file/{file_id}',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'api key' in data['error'].lower()
    
    def test_get_scan_status_not_found(self, auth_tokens):
        """Test getting status of a non-existent scan."""
        # Generate a random UUID that doesn't exist
        random_id = str(uuid.uuid4())
        
        response = self.client.get(
            f'/api/scan/{random_id}/status',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'}
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_get_scan_results_not_found(self, auth_tokens):
        """Test getting results of a non-existent scan."""
        # Generate a random UUID that doesn't exist
        random_id = str(uuid.uuid4())
        
        response = self.client.get(
            f'/api/scan/{random_id}/results',
            headers={'Authorization': f'Bearer {auth_tokens["access_token"]}'}
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
"""