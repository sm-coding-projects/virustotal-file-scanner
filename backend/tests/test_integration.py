"""
Integration tests for the VirusTotal File Scanner application.

These tests verify complete workflows and API interactions across multiple components.
"""
import json
import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from io import BytesIO
from backend.models.database import db, User, ApiKey, File, Scan, ScanResult, ScanStatus

@pytest.mark.usefixtures('client_class')
class TestUserWorkflow:
    """Test the complete user workflow from registration to API key management."""
    
    def test_register_login_add_api_key_workflow(self):
        """Test the complete workflow of user registration, login, and API key management."""
        # Step 1: Register a new user
        register_response = self.client.post(
            '/api/auth/register',
            json={
                'username': 'integrationuser',
                'email': 'integration@example.com',
                'password': 'integration123'
            }
        )
        assert register_response.status_code == 201
        register_data = json.loads(register_response.data)
        assert 'message' in register_data
        assert 'User registered successfully' in register_data['message']
        
        # Step 2: Login with the new user
        login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'integrationuser',
                'password': 'integration123'
            }
        )
        assert login_response.status_code == 200
        login_data = json.loads(login_response.data)
        assert 'access_token' in login_data
        assert 'refresh_token' in login_data
        
        access_token = login_data['access_token']
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        
        # Step 3: Get user profile
        profile_response = self.client.get(
            '/api/auth/profile',
            headers=auth_headers
        )
        assert profile_response.status_code == 200
        profile_data = json.loads(profile_response.data)
        assert 'username' in profile_data
        assert profile_data['username'] == 'integrationuser'
        
        # Step 4: Add an API key with validation mocked
        with patch('backend.services.virustotal.VirusTotalService.validate_api_key') as mock_validate:
            mock_validate.return_value = (True, None)
            
            add_key_response = self.client.post(
                '/api/keys/',
                headers=auth_headers,
                json={
                    'name': 'Integration Test Key',
                    'key_value': 'test_api_key_12345'
                }
            )
            assert add_key_response.status_code == 201
            add_key_data = json.loads(add_key_response.data)
            assert 'api_key' in add_key_data
            assert add_key_data['api_key']['name'] == 'Integration Test Key'
            
            api_key_id = add_key_data['api_key']['id']
        
        # Step 5: Get all API keys
        keys_response = self.client.get(
            '/api/keys/',
            headers=auth_headers
        )
        assert keys_response.status_code == 200
        keys_data = json.loads(keys_response.data)
        assert 'api_keys' in keys_data
        assert len(keys_data['api_keys']) == 1
        assert keys_data['api_keys'][0]['name'] == 'Integration Test Key'
        
        # Step 6: Update the API key
        update_key_response = self.client.put(
            f'/api/keys/{api_key_id}',
            headers=auth_headers,
            json={
                'name': 'Updated Integration Key',
                'is_active': False
            }
        )
        assert update_key_response.status_code == 200
        update_key_data = json.loads(update_key_response.data)
        assert 'api_key' in update_key_data
        assert update_key_data['api_key']['name'] == 'Updated Integration Key'
        assert update_key_data['api_key']['is_active'] is False
        
        # Step 7: Delete the API key
        delete_key_response = self.client.delete(
            f'/api/keys/{api_key_id}',
            headers=auth_headers
        )
        assert delete_key_response.status_code == 200
        delete_key_data = json.loads(delete_key_response.data)
        assert 'message' in delete_key_data
        assert 'deleted successfully' in delete_key_data['message']
        
        # Step 8: Verify the key is deleted
        keys_response = self.client.get(
            '/api/keys/',
            headers=auth_headers
        )
        assert keys_response.status_code == 200
        keys_data = json.loads(keys_response.data)
        assert 'api_keys' in keys_data
        assert len(keys_data['api_keys']) == 0

@pytest.mark.usefixtures('client_class')
class TestFileUploadAndScanWorkflow:
    """Test the complete workflow of file upload and scanning."""
    
    @pytest.fixture
    def auth_setup(self):
        """Set up authentication and API key for testing."""
        # Register a new user
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'fileuser',
                'email': 'file@example.com',
                'password': 'filepassword123'
            }
        )
        
        # Login
        login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'fileuser',
                'password': 'filepassword123'
            }
        )
        login_data = json.loads(login_response.data)
        access_token = login_data['access_token']
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        
        # Add API key with mocked validation
        with patch('backend.services.virustotal.VirusTotalService.validate_api_key') as mock_validate:
            mock_validate.return_value = (True, None)
            
            add_key_response = self.client.post(
                '/api/keys/',
                headers=auth_headers,
                json={
                    'name': 'File Test Key',
                    'key_value': 'file_test_api_key_12345'
                }
            )
            add_key_data = json.loads(add_key_response.data)
            api_key_id = add_key_data['api_key']['id']
        
        return {
            'auth_headers': auth_headers,
            'api_key_id': api_key_id
        }
    
    def test_file_upload_and_scan_workflow(self, auth_setup):
        """Test the complete workflow of uploading a file and scanning it."""
        auth_headers = auth_setup['auth_headers']
        api_key_id = auth_setup['api_key_id']
        
        # Step 1: Upload a test file
        test_file_content = b'This is a test file for scanning.'
        test_file = BytesIO(test_file_content)
        
        with patch('backend.api.files.secure_filename', return_value='test_file.txt'):
            upload_response = self.client.post(
                '/api/files/upload',
                headers=auth_headers,
                data={
                    'file': (test_file, 'test_file.txt')
                },
                content_type='multipart/form-data'
            )
            assert upload_response.status_code == 201
            upload_data = json.loads(upload_response.data)
            assert 'id' in upload_data
            assert 'filename' in upload_data
            assert upload_data['filename'] == 'test_file.txt'
            
            file_id = upload_data['id']
        
        # Step 2: Get the uploaded file details
        file_response = self.client.get(
            f'/api/files/{file_id}',
            headers=auth_headers
        )
        assert file_response.status_code == 200
        file_data = json.loads(file_response.data)
        assert file_data['id'] == file_id
        assert file_data['filename'] == 'test_file.txt'
        
        # Step 3: Initiate a scan with mocked VirusTotal service
        with patch('backend.services.virustotal.VirusTotalService.scan_file') as mock_scan:
            mock_scan.return_value = ('test_scan_id_12345', None)
            
            scan_response = self.client.post(
                f'/api/scan/file/{file_id}',
                headers=auth_headers,
                json={
                    'api_key_id': api_key_id
                }
            )
            assert scan_response.status_code == 202
            scan_data = json.loads(scan_response.data)
            assert 'scan_id' in scan_data
            assert scan_data['status'] == 'pending'
            
            scan_id = scan_data['scan_id']
        
        # Step 4: Check scan status with mocked service
        with patch('backend.services.virustotal.VirusTotalService.get_scan_status') as mock_status:
            mock_status.return_value = ('completed', None)
            
            status_response = self.client.get(
                f'/api/scan/{scan_id}/status',
                headers=auth_headers
            )
            assert status_response.status_code == 200
            status_data = json.loads(status_response.data)
            assert status_data['scan_id'] == scan_id
            assert status_data['status'] == 'completed'
        
        # Step 5: Get scan results with mocked service
        with patch('backend.services.virustotal.VirusTotalService.get_scan_results') as mock_results:
            # Create a mock scan result
            mock_results.return_value = {
                'stats': {
                    'malicious': 0,
                    'suspicious': 0,
                    'harmless': 60,
                    'undetected': 10
                },
                'results': [
                    {
                        'engine_name': 'TestAV1',
                        'engine_version': '1.0',
                        'result': None,
                        'category': 'harmless',
                        'update_date': '2023-01-01'
                    },
                    {
                        'engine_name': 'TestAV2',
                        'engine_version': '2.0',
                        'result': None,
                        'category': 'harmless',
                        'update_date': '2023-01-01'
                    }
                ]
            }
            
            results_response = self.client.get(
                f'/api/scan/{scan_id}/results',
                headers=auth_headers
            )
            assert results_response.status_code == 200
            results_data = json.loads(results_response.data)
            assert results_data['scan_id'] == scan_id
            assert 'results' in results_data
            assert len(results_data['results']) == 2
            assert results_data['results'][0]['engine_name'] == 'TestAV1'
            assert results_data['summary']['stats']['malicious'] == 0
            assert results_data['summary']['stats']['harmless'] == 60
        
        # Step 6: Delete the file
        delete_response = self.client.delete(
            f'/api/files/{file_id}',
            headers=auth_headers
        )
        assert delete_response.status_code == 200
        delete_data = json.loads(delete_response.data)
        assert 'message' in delete_data
        assert 'deleted successfully' in delete_data['message']
        
        # Step 7: Verify the file is deleted
        file_response = self.client.get(
            f'/api/files/{file_id}',
            headers=auth_headers
        )
        assert file_response.status_code == 404

@pytest.mark.usefixtures('client_class')
class TestMultiUserWorkflow:
    """Test workflows involving multiple users."""
    
    def test_file_isolation_between_users(self):
        """Test that files are properly isolated between different users."""
        # Step 1: Register two users
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'user1',
                'email': 'user1@example.com',
                'password': 'password123'
            }
        )
        
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'user2',
                'email': 'user2@example.com',
                'password': 'password123'
            }
        )
        
        # Step 2: Login as user1
        login1_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'user1',
                'password': 'password123'
            }
        )
        login1_data = json.loads(login1_response.data)
        user1_token = login1_data['access_token']
        user1_headers = {'Authorization': f'Bearer {user1_token}'}
        
        # Step 3: Login as user2
        login2_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'user2',
                'password': 'password123'
            }
        )
        login2_data = json.loads(login2_response.data)
        user2_token = login2_data['access_token']
        user2_headers = {'Authorization': f'Bearer {user2_token}'}
        
        # Step 4: User1 uploads a file
        test_file1 = BytesIO(b'User1 test file')
        
        with patch('backend.api.files.secure_filename', return_value='user1_file.txt'):
            upload1_response = self.client.post(
                '/api/files/upload',
                headers=user1_headers,
                data={
                    'file': (test_file1, 'user1_file.txt')
                },
                content_type='multipart/form-data'
            )
            assert upload1_response.status_code == 201
            upload1_data = json.loads(upload1_response.data)
            user1_file_id = upload1_data['id']
        
        # Step 5: User2 uploads a file
        test_file2 = BytesIO(b'User2 test file')
        
        with patch('backend.api.files.secure_filename', return_value='user2_file.txt'):
            upload2_response = self.client.post(
                '/api/files/upload',
                headers=user2_headers,
                data={
                    'file': (test_file2, 'user2_file.txt')
                },
                content_type='multipart/form-data'
            )
            assert upload2_response.status_code == 201
            upload2_data = json.loads(upload2_response.data)
            user2_file_id = upload2_data['id']
        
        # Step 6: User1 tries to access User2's file
        file_response = self.client.get(
            f'/api/files/{user2_file_id}',
            headers=user1_headers
        )
        assert file_response.status_code == 403  # Should be forbidden
        
        # Step 7: User2 tries to access User1's file
        file_response = self.client.get(
            f'/api/files/{user1_file_id}',
            headers=user2_headers
        )
        assert file_response.status_code == 403  # Should be forbidden
        
        # Step 8: User1 tries to delete User2's file
        delete_response = self.client.delete(
            f'/api/files/{user2_file_id}',
            headers=user1_headers
        )
        assert delete_response.status_code == 403  # Should be forbidden
        
        # Step 9: User2 tries to delete User1's file
        delete_response = self.client.delete(
            f'/api/files/{user1_file_id}',
            headers=user2_headers
        )
        assert delete_response.status_code == 403  # Should be forbidden
        
        # Step 10: Each user can access their own files
        file1_response = self.client.get(
            f'/api/files/{user1_file_id}',
            headers=user1_headers
        )
        assert file1_response.status_code == 200
        file1_data = json.loads(file1_response.data)
        assert file1_data['filename'] == 'user1_file.txt'
        
        file2_response = self.client.get(
            f'/api/files/{user2_file_id}',
            headers=user2_headers
        )
        assert file2_response.status_code == 200
        file2_data = json.loads(file2_response.data)
        assert file2_data['filename'] == 'user2_file.txt'
</content>