"""
Security-focused integration tests for the VirusTotal File Scanner application.

These tests verify security aspects across multiple components and workflows.
"""
import json
import os
import pytest
import tempfile
import time
from unittest.mock import patch, MagicMock
from io import BytesIO
from backend.models.database import db, User, ApiKey, File, Scan, ScanResult, ScanStatus

@pytest.mark.usefixtures('client_class')
class TestSecurityIntegration:
    """Test security aspects across multiple components."""
    
    def test_api_key_encryption_workflow(self):
        """Test that API keys are properly encrypted throughout the workflow."""
        # Step 1: Register a new user
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'securityuser',
                'email': 'security@example.com',
                'password': 'SecureP@ss123'
            }
        )
        
        # Step 2: Login with the new user
        login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'securityuser',
                'password': 'SecureP@ss123'
            }
        )
        login_data = json.loads(login_response.data)
        access_token = login_data['access_token']
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        
        # Step 3: Add an API key with validation mocked
        api_key_value = 'test_secure_api_key_12345'
        with patch('backend.services.virustotal.VirusTotalService.validate_api_key') as mock_validate:
            mock_validate.return_value = (True, None)
            
            add_key_response = self.client.post(
                '/api/keys/',
                headers=auth_headers,
                json={
                    'name': 'Security Test Key',
                    'key_value': api_key_value
                }
            )
            add_key_data = json.loads(add_key_response.data)
            api_key_id = add_key_data['api_key']['id']
        
        # Step 4: Verify the API key is not exposed in the response
        assert 'key_value' not in add_key_data['api_key']
        
        # Step 5: Get the API key and verify it's not exposed
        get_key_response = self.client.get(
            f'/api/keys/{api_key_id}',
            headers=auth_headers
        )
        get_key_data = json.loads(get_key_response.data)
        assert 'key_value' not in get_key_data['api_key']
        
        # Step 6: Verify the API key is encrypted in the database
        with self.client.application.app_context():
            api_key = ApiKey.query.filter_by(id=api_key_id).first()
            assert api_key is not None
            assert api_key.key_value != api_key_value  # Should be encrypted
            
            # Verify we can decrypt it correctly
            from backend.utils.encryption import decrypt_value
            decrypted_key = decrypt_value(api_key.key_value)
            assert decrypted_key == api_key_value
    
    def test_authentication_security_workflow(self):
        """Test authentication security throughout the workflow."""
        # Step 1: Register a user with a weak password
        weak_response = self.client.post(
            '/api/auth/register',
            json={
                'username': 'weakuser',
                'email': 'weak@example.com',
                'password': 'weak'
            }
        )
        # Should be rejected
        assert weak_response.status_code == 400
        
        # Step 2: Register with a strong password
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'stronguser',
                'email': 'strong@example.com',
                'password': 'StrongP@ss123'
            }
        )
        
        # Step 3: Login with incorrect password
        wrong_login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'stronguser',
                'password': 'WrongP@ss123'
            }
        )
        assert wrong_login_response.status_code == 401
        
        # Step 4: Login with correct password
        login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'stronguser',
                'password': 'StrongP@ss123'
            }
        )
        assert login_response.status_code == 200
        login_data = json.loads(login_response.data)
        access_token = login_data['access_token']
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        
        # Step 5: Access protected endpoint
        profile_response = self.client.get(
            '/api/auth/profile',
            headers=auth_headers
        )
        assert profile_response.status_code == 200
        
        # Step 6: Access with invalid token
        invalid_headers = {'Authorization': 'Bearer invalid_token'}
        invalid_response = self.client.get(
            '/api/auth/profile',
            headers=invalid_headers
        )
        assert invalid_response.status_code == 401
        
        # Step 7: Access with expired token
        with patch('flask_jwt_extended.utils.get_jwt') as mock_jwt:
            # Simulate an expired token
            mock_jwt.return_value = {'exp': int(time.time()) - 3600}
            
            expired_response = self.client.get(
                '/api/auth/profile',
                headers=auth_headers
            )
            assert expired_response.status_code == 401
        
        # Step 8: Logout
        logout_response = self.client.post(
            '/api/auth/logout',
            headers=auth_headers
        )
        assert logout_response.status_code == 200
        
        # Step 9: Try to use token after logout
        after_logout_response = self.client.get(
            '/api/auth/profile',
            headers=auth_headers
        )
        assert after_logout_response.status_code == 401
    
    def test_file_upload_security_workflow(self):
        """Test file upload security throughout the workflow."""
        # Step 1: Register and login
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'fileuser',
                'email': 'file@example.com',
                'password': 'SecureP@ss123'
            }
        )
        
        login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'fileuser',
                'password': 'SecureP@ss123'
            }
        )
        login_data = json.loads(login_response.data)
        access_token = login_data['access_token']
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        
        # Step 2: Try to upload a file with path traversal in filename
        traversal_file = BytesIO(b'path traversal attempt')
        traversal_response = self.client.post(
            '/api/files/upload',
            headers=auth_headers,
            data={
                'file': (traversal_file, '../../../etc/passwd')
            },
            content_type='multipart/form-data'
        )
        
        # Should sanitize the filename
        assert traversal_response.status_code == 201
        traversal_data = json.loads(traversal_response.data)
        assert '../' not in traversal_data['filename']
        assert 'etc/passwd' not in traversal_data['filename']
        
        # Step 3: Try to upload a file with malicious content
        xss_file = BytesIO(b'<script>alert("XSS")</script>')
        xss_response = self.client.post(
            '/api/files/upload',
            headers=auth_headers,
            data={
                'file': (xss_file, 'xss.html')
            },
            content_type='multipart/form-data'
        )
        
        # Should reject HTML files
        assert xss_response.status_code == 400
        
        # Step 4: Try to upload an executable file
        exe_file = BytesIO(b'#!/bin/bash\necho "Malicious script"')
        exe_response = self.client.post(
            '/api/files/upload',
            headers=auth_headers,
            data={
                'file': (exe_file, 'malicious.sh')
            },
            content_type='multipart/form-data'
        )
        
        # Should reject executable files
        assert exe_response.status_code == 400
        
        # Step 5: Upload a valid file
        valid_file = BytesIO(b'Valid file content')
        valid_response = self.client.post(
            '/api/files/upload',
            headers=auth_headers,
            data={
                'file': (valid_file, 'valid.txt')
            },
            content_type='multipart/form-data'
        )
        
        assert valid_response.status_code == 201
        valid_data = json.loads(valid_response.data)
        file_id = valid_data['id']
        
        # Step 6: Verify file permissions
        # Register a second user
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'otheruser',
                'email': 'other@example.com',
                'password': 'SecureP@ss123'
            }
        )
        
        other_login = self.client.post(
            '/api/auth/login',
            json={
                'username': 'otheruser',
                'password': 'SecureP@ss123'
            }
        )
        other_token = json.loads(other_login.data)['access_token']
        other_headers = {'Authorization': f'Bearer {other_token}'}
        
        # Try to access first user's file
        other_access = self.client.get(
            f'/api/files/{file_id}',
            headers=other_headers
        )
        
        # Should be denied
        assert other_access.status_code == 403
        
        # Step 7: Secure deletion
        delete_response = self.client.delete(
            f'/api/files/{file_id}',
            headers=auth_headers
        )
        assert delete_response.status_code == 200
        
        # Verify file is deleted from database
        with self.client.application.app_context():
            file = File.query.filter_by(id=file_id).first()
            assert file is None

@pytest.mark.usefixtures('client_class')
class TestSecurityHeadersIntegration:
    """Test security headers across the application."""
    
    def test_security_headers_present(self):
        """Test that security headers are present in responses."""
        # Check public endpoint
        response = self.client.get('/')
        
        # Verify security headers
        assert 'Content-Security-Policy' in response.headers
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-XSS-Protection' in response.headers
        assert 'Strict-Transport-Security' in response.headers
        
        # Check specific values
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.headers['X-Frame-Options'] == 'DENY'
        assert 'max-age=31536000' in response.headers['Strict-Transport-Security']
    
    def test_csrf_protection(self):
        """Test CSRF protection for state-changing operations."""
        # Register and login
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'csrfuser',
                'email': 'csrf@example.com',
                'password': 'SecureP@ss123'
            }
        )
        
        login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'csrfuser',
                'password': 'SecureP@ss123'
            }
        )
        login_data = json.loads(login_response.data)
        access_token = login_data['access_token']
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        
        # Get CSRF token
        csrf_token = login_response.headers.get('X-CSRF-Token')
        assert csrf_token is not None
        
        # Try state-changing operation without CSRF token
        no_csrf_response = self.client.post(
            '/api/auth/change-password',
            headers=auth_headers,
            json={
                'current_password': 'SecureP@ss123',
                'new_password': 'NewSecureP@ss123'
            }
        )
        
        # Should be rejected
        assert no_csrf_response.status_code == 400
        
        # Try with CSRF token
        csrf_headers = auth_headers.copy()
        csrf_headers['X-CSRF-Token'] = csrf_token
        
        csrf_response = self.client.post(
            '/api/auth/change-password',
            headers=csrf_headers,
            json={
                'current_password': 'SecureP@ss123',
                'new_password': 'NewSecureP@ss123'
            }
        )
        
        # Should succeed
        assert csrf_response.status_code == 200

@pytest.mark.usefixtures('client_class')
class TestRateLimitingIntegration:
    """Test rate limiting across the application."""
    
    def test_login_rate_limiting(self):
        """Test rate limiting for login attempts."""
        # Register a user
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'ratelimituser',
                'email': 'ratelimit@example.com',
                'password': 'SecureP@ss123'
            }
        )
        
        # Make multiple failed login attempts
        for i in range(10):
            response = self.client.post(
                '/api/auth/login',
                json={
                    'username': 'ratelimituser',
                    'password': f'wrong_password_{i}'
                }
            )
            
            # Check if rate limiting kicks in
            if response.status_code == 429:
                # Rate limiting detected
                assert 'X-RateLimit-Limit' in response.headers
                assert 'X-RateLimit-Remaining' in response.headers
                assert 'X-RateLimit-Reset' in response.headers
                assert int(response.headers['X-RateLimit-Remaining']) <= 0
                
                data = json.loads(response.data)
                assert 'error' in data
                assert 'rate limit' in data['error'].lower()
                assert 'retry_after' in data
                break
            
            # If we've made it through all attempts without rate limiting, check headers
            if i == 9:
                assert 'X-RateLimit-Remaining' in response.headers
                remaining = int(response.headers['X-RateLimit-Remaining'])
                assert remaining >= 0
    
    def test_api_endpoint_rate_limiting(self):
        """Test rate limiting for API endpoints."""
        # Register and login
        self.client.post(
            '/api/auth/register',
            json={
                'username': 'apiratelimit',
                'email': 'apiratelimit@example.com',
                'password': 'SecureP@ss123'
            }
        )
        
        login_response = self.client.post(
            '/api/auth/login',
            json={
                'username': 'apiratelimit',
                'password': 'SecureP@ss123'
            }
        )
        login_data = json.loads(login_response.data)
        access_token = login_data['access_token']
        auth_headers = {'Authorization': f'Bearer {access_token}'}
        
        # Make multiple rapid requests to an API endpoint
        for i in range(100):  # High number to trigger rate limiting
            response = self.client.get(
                '/api/files/',
                headers=auth_headers
            )
            
            # Check if rate limiting kicks in
            if response.status_code == 429:
                # Rate limiting detected
                data = json.loads(response.data)
                assert 'error' in data
                assert 'rate limit' in data['error'].lower()
                break
            
            # If we've made it through all requests without rate limiting, check headers
            if i == 99:
                assert 'X-RateLimit-Remaining' in response.headers
                remaining = int(response.headers['X-RateLimit-Remaining'])
                assert remaining >= 0