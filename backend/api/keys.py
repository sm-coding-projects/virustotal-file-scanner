"""
API key management endpoints for the VirusTotal File Scanner application.
"""
import uuid
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.models.database import db, User, ApiKey
from backend.services.virustotal import VirusTotalService
from backend.utils.encryption import encrypt_value, decrypt_value

keys_bp = Blueprint('keys', __name__, url_prefix='/api/keys')

@keys_bp.route('/', methods=['GET'])
@jwt_required()
def get_api_keys():
    """
    Get all API keys for the current user.
    
    Returns:
        JSON response with API keys
    """
    current_user_id = get_jwt_identity()
    
    try:
        # Get all API keys for the current user
        api_keys = ApiKey.query.filter_by(user_id=current_user_id).all()
        
        # Format API keys for response (don't include the actual key value)
        keys_data = [{
            'id': str(key.id),
            'name': key.name,
            'is_active': key.is_active,
            'created_at': key.created_at.isoformat(),
            'updated_at': key.updated_at.isoformat()
        } for key in api_keys]
        
        return jsonify({
            'api_keys': keys_data
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving API keys: {str(e)}")
        return jsonify({'error': 'Failed to retrieve API keys'}), 500


@keys_bp.route('/', methods=['POST'])
@jwt_required()
def create_api_key():
    """
    Create a new API key.
    
    Request body:
    {
        "name": "string",
        "key_value": "string"
    }
    
    Returns:
        JSON response with created API key
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    # Validate required fields
    if not all(k in data for k in ('name', 'key_value')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Validate API key with VirusTotal
    vt_service = VirusTotalService()
    is_valid, error_message = vt_service.validate_api_key(data['key_value'])
    
    if not is_valid:
        return jsonify({'error': f'Invalid API key: {error_message}'}), 400
    
    try:
        # Encrypt the API key
        encrypted_key = encrypt_value(data['key_value'])
        
        # Create new API key
        api_key = ApiKey(
            id=uuid.uuid4(),
            user_id=current_user_id,
            name=data['name'],
            key_value=encrypted_key,
            is_active=True
        )
        
        db.session.add(api_key)
        db.session.commit()
        
        return jsonify({
            'message': 'API key created successfully',
            'api_key': {
                'id': str(api_key.id),
                'name': api_key.name,
                'is_active': api_key.is_active,
                'created_at': api_key.created_at.isoformat(),
                'updated_at': api_key.updated_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating API key: {str(e)}")
        return jsonify({'error': 'Failed to create API key'}), 500


@keys_bp.route('/<key_id>', methods=['GET'])
@jwt_required()
def get_api_key(key_id):
    """
    Get a specific API key.
    
    Args:
        key_id: API key ID
        
    Returns:
        JSON response with API key details
    """
    current_user_id = get_jwt_identity()
    
    try:
        # Get API key by ID and user ID
        api_key = ApiKey.query.filter_by(id=key_id, user_id=current_user_id).first()
        
        if not api_key:
            return jsonify({'error': 'API key not found'}), 404
        
        # Format API key for response (don't include the actual key value)
        key_data = {
            'id': str(api_key.id),
            'name': api_key.name,
            'is_active': api_key.is_active,
            'created_at': api_key.created_at.isoformat(),
            'updated_at': api_key.updated_at.isoformat()
        }
        
        return jsonify({
            'api_key': key_data
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving API key: {str(e)}")
        return jsonify({'error': 'Failed to retrieve API key'}), 500


@keys_bp.route('/<key_id>', methods=['PUT'])
@jwt_required()
def update_api_key(key_id):
    """
    Update an API key.
    
    Args:
        key_id: API key ID
        
    Request body:
    {
        "name": "string" (optional),
        "key_value": "string" (optional),
        "is_active": boolean (optional)
    }
    
    Returns:
        JSON response with updated API key
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    # Check if there's anything to update
    if not any(k in data for k in ('name', 'key_value', 'is_active')):
        return jsonify({'error': 'No update data provided'}), 400
    
    try:
        # Get API key by ID and user ID
        api_key = ApiKey.query.filter_by(id=key_id, user_id=current_user_id).first()
        
        if not api_key:
            return jsonify({'error': 'API key not found'}), 404
        
        # Update name if provided
        if 'name' in data:
            api_key.name = data['name']
        
        # Update key value if provided
        if 'key_value' in data:
            # Validate new API key with VirusTotal
            vt_service = VirusTotalService()
            is_valid, error_message = vt_service.validate_api_key(data['key_value'])
            
            if not is_valid:
                return jsonify({'error': f'Invalid API key: {error_message}'}), 400
            
            # Encrypt the new API key
            api_key.key_value = encrypt_value(data['key_value'])
        
        # Update active status if provided
        if 'is_active' in data:
            api_key.is_active = bool(data['is_active'])
        
        db.session.commit()
        
        return jsonify({
            'message': 'API key updated successfully',
            'api_key': {
                'id': str(api_key.id),
                'name': api_key.name,
                'is_active': api_key.is_active,
                'created_at': api_key.created_at.isoformat(),
                'updated_at': api_key.updated_at.isoformat()
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating API key: {str(e)}")
        return jsonify({'error': 'Failed to update API key'}), 500


@keys_bp.route('/<key_id>', methods=['DELETE'])
@jwt_required()
def delete_api_key(key_id):
    """
    Delete an API key.
    
    Args:
        key_id: API key ID
        
    Returns:
        JSON response with deletion confirmation
    """
    current_user_id = get_jwt_identity()
    
    try:
        # Get API key by ID and user ID
        api_key = ApiKey.query.filter_by(id=key_id, user_id=current_user_id).first()
        
        if not api_key:
            return jsonify({'error': 'API key not found'}), 404
        
        db.session.delete(api_key)
        db.session.commit()
        
        return jsonify({
            'message': 'API key deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting API key: {str(e)}")
        return jsonify({'error': 'Failed to delete API key'}), 500


@keys_bp.route('/validate', methods=['POST'])
@jwt_required()
def validate_api_key():
    """
    Validate an API key with VirusTotal.
    
    Request body:
    {
        "key_value": "string"
    }
    
    Returns:
        JSON response with validation result
    """
    data = request.get_json()
    
    # Validate required fields
    if 'key_value' not in data or not data['key_value']:
        return jsonify({'error': 'API key is required'}), 400
    
    # Validate API key with VirusTotal
    vt_service = VirusTotalService()
    is_valid, error_message = vt_service.validate_api_key(data['key_value'])
    
    if is_valid:
        return jsonify({
            'valid': True,
            'message': 'API key is valid'
        }), 200
    else:
        return jsonify({
            'valid': False,
            'message': error_message
        }), 200