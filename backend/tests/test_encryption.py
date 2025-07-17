"""
Tests for the encryption utilities.
"""
import pytest
from unittest.mock import patch, MagicMock
from backend.utils.encryption import generate_key, encrypt_value, decrypt_value

def test_generate_key():
    """Test key generation from secret key and salt."""
    # Test with string secret key
    key1 = generate_key("test_secret_key")
    assert key1 is not None
    assert isinstance(key1, bytes)
    assert len(key1) > 0
    
    # Test with bytes secret key
    key2 = generate_key(b"test_secret_key")
    assert key2 is not None
    assert isinstance(key2, bytes)
    assert len(key2) > 0
    
    # Test with custom salt
    key3 = generate_key("test_secret_key", salt=b"custom_salt")
    assert key3 is not None
    assert isinstance(key3, bytes)
    assert len(key3) > 0
    
    # Test that different salts produce different keys
    key4 = generate_key("test_secret_key", salt=b"another_salt")
    assert key3 != key4
    
    # Test that same inputs produce same key (deterministic)
    key5 = generate_key("test_secret_key", salt=b"custom_salt")
    assert key3 == key5

def test_encrypt_decrypt_cycle(app):
    """Test encryption and decryption cycle."""
    with app.app_context():
        # Test with string value
        original_value = "sensitive_api_key_12345"
        encrypted = encrypt_value(original_value)
        assert encrypted is not None
        assert encrypted != original_value
        
        decrypted = decrypt_value(encrypted)
        assert decrypted == original_value
        
        # Test with empty value
        assert encrypt_value(None) is None
        assert decrypt_value(None) is None
        
        # Test with empty string
        empty_encrypted = encrypt_value("")
        assert empty_encrypted is not None
        assert decrypt_value(empty_encrypted) == ""

def test_encryption_different_values(app):
    """Test that different values encrypt to different ciphertexts."""
    with app.app_context():
        value1 = "api_key_1"
        value2 = "api_key_2"
        
        encrypted1 = encrypt_value(value1)
        encrypted2 = encrypt_value(value2)
        
        assert encrypted1 != encrypted2

def test_encryption_same_value_different_results(app):
    """Test that encrypting the same value twice produces different ciphertexts (due to random IV)."""
    with app.app_context():
        value = "api_key_12345"
        
        encrypted1 = encrypt_value(value)
        encrypted2 = encrypt_value(value)
        
        # Encrypted values should be different due to random IV
        assert encrypted1 != encrypted2
        
        # But both should decrypt to the original value
        assert decrypt_value(encrypted1) == value
        assert decrypt_value(encrypted2) == value

def test_decrypt_invalid_value(app):
    """Test decryption with invalid encrypted value."""
    with app.app_context():
        # Test with invalid format
        assert decrypt_value("not_valid_encrypted_value") is None
        
        # Test with valid format but incorrect key/data
        assert decrypt_value("gAAAAABkX7H_invalid_encrypted_value") is None

def test_key_rotation_simulation(app):
    """Test simulating key rotation scenario."""
    with app.app_context():
        # Encrypt with current secret key
        original_value = "api_key_for_rotation_test"
        encrypted = encrypt_value(original_value)
        
        # Simulate key rotation by changing the secret key
        with patch('flask.current_app.config') as mock_config:
            mock_config.__getitem__.return_value = "new_rotated_secret_key"
            
            # Decryption should fail with new key
            assert decrypt_value(encrypted) is None
            
            # New encryption should use new key
            new_encrypted = encrypt_value(original_value)
            assert new_encrypted != encrypted
            assert decrypt_value(new_encrypted) == original_value