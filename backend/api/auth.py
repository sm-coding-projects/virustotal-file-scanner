"""
Authentication module for the VirusTotal File Scanner application.
"""
import uuid
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, create_refresh_token, 
    jwt_required, get_jwt_identity
)
from backend.models.database import db, User
from backend.api.auth_helpers import validate_registration_data, get_user_data

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    
    Request body:
    {
        "username": "string",
        "email": "string",
        "password": "string"
    }
    
    Returns:
        JSON response with user information or error message
    """
    data = request.get_json()
    
    # Validate input data
    is_valid, error_message = validate_registration_data(data)
    if not is_valid:
        return jsonify({'error': error_message}), 400
    
    # Check if username or email already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    # Create new user
    try:
        user = User(
            id=uuid.uuid4(),
            username=data['username'],
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            is_admin=False  # Default to non-admin user
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': get_user_data(user)
        }), 201
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error registering user: {str(e)}")
        return jsonify({'error': 'Failed to register user'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate a user and return JWT tokens.
    
    Request body:
    {
        "username": "string",
        "password": "string"
    }
    
    Returns:
        JSON response with access and refresh tokens or error message
    """
    data = request.get_json()
    
    # Validate required fields
    if not all(k in data for k in ('username', 'password')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Find user by username or email
    user = User.query.filter(
        (User.username == data['username']) | (User.email == data['username'])
    ).first()
    
    # Check if user exists and password is correct
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Create tokens
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    
    # Log successful login
    current_app.logger.info(f"User {user.username} logged in successfully")
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': get_user_data(user)
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token using refresh token.
    
    Returns:
        JSON response with new access token
    """
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    
    return jsonify({'access_token': access_token}), 200


@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """
    Get current user profile.
    
    Returns:
        JSON response with user profile information
    """
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=current_user_id).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user': get_user_data(user)
    }), 200


@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """
    Update current user profile.
    
    Request body:
    {
        "username": "string" (optional),
        "email": "string" (optional),
        "current_password": "string" (required for password change),
        "new_password": "string" (optional)
    }
    
    Returns:
        JSON response with updated user information
    """
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=current_user_id).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    try:
        # Update username if provided
        if 'username' in data and data['username'] != user.username:
            # Check if username is already taken
            if User.query.filter_by(username=data['username']).first():
                return jsonify({'error': 'Username already exists'}), 409
            user.username = data['username']
        
        # Update email if provided
        if 'email' in data and data['email'] != user.email:
            # Check if email is already taken
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'error': 'Email already exists'}), 409
            user.email = data['email']
        
        # Update password if provided
        if 'new_password' in data and 'current_password' in data:
            if not check_password_hash(user.password_hash, data['current_password']):
                return jsonify({'error': 'Current password is incorrect'}), 401
            user.password_hash = generate_password_hash(data['new_password'])
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': get_user_data(user)
        }), 200
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating user profile: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logout a user.
    
    Note: Since JWT tokens are stateless, this endpoint doesn't actually invalidate the token.
    For a complete logout solution, the client should discard the token and a token blacklist
    should be implemented on the server side.
    
    Returns:
        JSON response with logout confirmation
    """
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=current_user_id).first()
    
    if user:
        current_app.logger.info(f"User {user.username} logged out")
    
    return jsonify({'message': 'Successfully logged out'}), 200