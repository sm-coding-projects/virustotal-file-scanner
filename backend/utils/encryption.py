"""
Encryption utilities for the VirusTotal File Scanner application.
"""
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app

def generate_key(secret_key, salt=b'virustotal_scanner'):
    """
    Generate a Fernet key from a secret key and salt.
    
    Args:
        secret_key: Secret key string
        salt: Salt bytes
        
    Returns:
        Fernet key
    """
    # Convert string secret key to bytes if needed
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    
    # Use PBKDF2 to derive a key from the secret key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key))
    return key

def encrypt_value(value):
    """
    Encrypt a value using the application's secret key.
    
    Args:
        value: String value to encrypt
        
    Returns:
        Encrypted value as a string
    """
    if not value:
        return None
    
    # Convert string to bytes if needed
    if isinstance(value, str):
        value = value.encode()
    
    # Generate key from application secret key
    key = generate_key(current_app.config['SECRET_KEY'])
    
    # Create Fernet cipher and encrypt
    cipher = Fernet(key)
    encrypted_value = cipher.encrypt(value)
    
    # Return as string
    return encrypted_value.decode()

def decrypt_value(encrypted_value):
    """
    Decrypt a value using the application's secret key.
    
    Args:
        encrypted_value: Encrypted string value
        
    Returns:
        Decrypted value as a string
    """
    if not encrypted_value:
        return None
    
    # Convert string to bytes if needed
    if isinstance(encrypted_value, str):
        encrypted_value = encrypted_value.encode()
    
    # Generate key from application secret key
    key = generate_key(current_app.config['SECRET_KEY'])
    
    # Create Fernet cipher and decrypt
    cipher = Fernet(key)
    try:
        decrypted_value = cipher.decrypt(encrypted_value)
        return decrypted_value.decode()
    except Exception as e:
        current_app.logger.error(f"Error decrypting value: {str(e)}")
        return None