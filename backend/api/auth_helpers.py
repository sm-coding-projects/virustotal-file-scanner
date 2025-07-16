"""
Authentication helper functions for the VirusTotal File Scanner application.
"""
from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from backend.models.database import User

def admin_required():
    """
    Decorator to require admin privileges for a route.
    
    Returns:
        Decorated function
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            user = User.query.filter_by(id=current_user_id).first()
            
            if not user or not user.is_admin:
                return jsonify({'error': 'Admin privileges required'}), 403
            
            return fn(*args, **kwargs)
        return decorator
    return wrapper

def validate_registration_data(data):
    """
    Validate user registration data.
    
    Args:
        data: Registration data dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check required fields
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing required field: {field}"
    
    # Validate username (alphanumeric, 3-64 chars)
    if not data['username'].isalnum() or len(data['username']) < 3 or len(data['username']) > 64:
        return False, "Username must be alphanumeric and between 3-64 characters"
    
    # Validate email format (basic check)
    if '@' not in data['email'] or '.' not in data['email'] or len(data['email']) > 120:
        return False, "Invalid email format"
    
    # Validate password strength (at least 8 chars)
    if len(data['password']) < 8:
        return False, "Password must be at least 8 characters long"
    
    return True, None

def get_user_data(user):
    """
    Get safe user data for API responses.
    
    Args:
        user: User model instance
        
    Returns:
        Dictionary with user data
    """
    return {
        'id': str(user.id),
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.isoformat(),
        'updated_at': user.updated_at.isoformat()
    }