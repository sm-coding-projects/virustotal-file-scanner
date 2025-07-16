"""
Tests for API key management endpoints.
"""
import json
import pytest
from unittest.mock import patch
from backend.models.database import ApiKey

@pytest.fixture
def api_key_data():
    """Fixture for API key test data."""
    return {
        'name': 'Test API Key',
        'key_value': 'test_api_key_12345'
    }

def test_get_api_keys(client, auth_headers):
    """Test getting all API keys for a user."""
    response = client.get('/api/keys/', headers=auth_headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'api_keys' in data
    assert isinstance(data['api_keys'], list)

@patch('backend.services.virustotal.VirusTotalService.validate_api_key')
def test_create_api_key_success(mock_validate, client, auth_headers, api_key_data):
    """Test creating a new API key successfully."""
    # Mock the validation to return success
    mock_validate.return_value = (True, None)
    
    response = client.post(
        '/api/keys/',
        headers=auth_headers,
        json=api_key_data
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'message' in data
    assert 'api_key' in data
    assert data['api_key']['name'] == api_key_data['name']
    assert 'id' in data['api_key']

@patch('backend.services.virustotal.VirusTotalService.validate_api_key')
def test_create_api_key_invalid(mock_validate, client, auth_headers, api_key_data):
    """Test creating a new API key with invalid key."""
    # Mock the validation to return failure
    mock_validate.return_value = (False, "Invalid API key")
    
    response = client.post(
        '/api/keys/',
        headers=auth_headers,
        json=api_key_data
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid API key' in data['error']

def test_create_api_key_missing_fields(client, auth_headers):
    """Test creating a new API key with missing fields."""
    response = client.post(
        '/api/keys/',
        headers=auth_headers,
        json={'name': 'Incomplete Key'}
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing required fields' in data['error']

@patch('backend.services.virustotal.VirusTotalService.validate_api_key')
def test_get_api_key(mock_validate, client, auth_headers, api_key_data):
    """Test getting a specific API key."""
    # Mock the validation to return success
    mock_validate.return_value = (True, None)
    
    # First create an API key
    create_response = client.post(
        '/api/keys/',
        headers=auth_headers,
        json=api_key_data
    )
    create_data = json.loads(create_response.data)
    key_id = create_data['api_key']['id']
    
    # Then get the API key
    response = client.get(f'/api/keys/{key_id}', headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'api_key' in data
    assert data['api_key']['id'] == key_id
    assert data['api_key']['name'] == api_key_data['name']
    # Ensure the key value is not returned
    assert 'key_value' not in data['api_key']

def test_get_nonexistent_api_key(client, auth_headers):
    """Test getting a non-existent API key."""
    response = client.get('/api/keys/12345', headers=auth_headers)
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data

@patch('backend.services.virustotal.VirusTotalService.validate_api_key')
def test_update_api_key(mock_validate, client, auth_headers, api_key_data):
    """Test updating an API key."""
    # Mock the validation to return success
    mock_validate.return_value = (True, None)
    
    # First create an API key
    create_response = client.post(
        '/api/keys/',
        headers=auth_headers,
        json=api_key_data
    )
    create_data = json.loads(create_response.data)
    key_id = create_data['api_key']['id']
    
    # Then update the API key
    update_data = {
        'name': 'Updated API Key',
        'is_active': False
    }
    response = client.put(
        f'/api/keys/{key_id}',
        headers=auth_headers,
        json=update_data
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'api_key' in data
    assert data['api_key']['name'] == update_data['name']
    assert data['api_key']['is_active'] == update_data['is_active']

@patch('backend.services.virustotal.VirusTotalService.validate_api_key')
def test_delete_api_key(mock_validate, client, auth_headers, api_key_data):
    """Test deleting an API key."""
    # Mock the validation to return success
    mock_validate.return_value = (True, None)
    
    # First create an API key
    create_response = client.post(
        '/api/keys/',
        headers=auth_headers,
        json=api_key_data
    )
    create_data = json.loads(create_response.data)
    key_id = create_data['api_key']['id']
    
    # Then delete the API key
    response = client.delete(f'/api/keys/{key_id}', headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    
    # Verify the key is deleted
    get_response = client.get(f'/api/keys/{key_id}', headers=auth_headers)
    assert get_response.status_code == 404

@patch('backend.services.virustotal.VirusTotalService.validate_api_key')
def test_validate_api_key_valid(mock_validate, client, auth_headers):
    """Test validating a valid API key."""
    # Mock the validation to return success
    mock_validate.return_value = (True, None)
    
    response = client.post(
        '/api/keys/validate',
        headers=auth_headers,
        json={'key_value': 'valid_api_key'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['valid'] is True

@patch('backend.services.virustotal.VirusTotalService.validate_api_key')
def test_validate_api_key_invalid(mock_validate, client, auth_headers):
    """Test validating an invalid API key."""
    # Mock the validation to return failure
    mock_validate.return_value = (False, "Invalid API key")
    
    response = client.post(
        '/api/keys/validate',
        headers=auth_headers,
        json={'key_value': 'invalid_api_key'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['valid'] is False
    assert 'message' in data