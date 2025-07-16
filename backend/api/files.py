"""
File upload and management API for the VirusTotal File Scanner application.
"""
import os
import hashlib
import uuid
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from backend.models.database import db, File, User

# Create blueprint for file operations
files_bp = Blueprint('files', __name__, url_prefix='/api/files')

def allowed_file(filename):
    """
    Check if the file extension is allowed.
    
    Args:
        filename: Name of the file to check
        
    Returns:
        Boolean indicating if the file extension is allowed
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def calculate_file_hashes(file_path):
    """
    Calculate MD5, SHA1, and SHA256 hashes for a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary containing the hash values
    """
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b''):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    
    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

@files_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    """
    Upload a file for scanning.
    
    Returns:
        JSON response with file information or error message
    """
    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    
    file = request.files['file']
    
    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Check if the file type is allowed
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Check file size
    if request.content_length > current_app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': f"File too large. Maximum size is {current_app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)} MB"}), 400
    
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=current_user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Create a secure filename and save the file
        filename = secure_filename(file.filename)
        # Create a unique directory for this upload using UUID
        upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], str(uuid.uuid4()))
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        # Calculate file hashes
        hashes = calculate_file_hashes(file_path)
        
        # Create file record in database
        new_file = File(
            user_id=user.id,
            filename=filename,
            file_size=os.path.getsize(file_path),
            mime_type=file.content_type,
            storage_path=file_path,
            hash_md5=hashes['md5'],
            hash_sha1=hashes['sha1'],
            hash_sha256=hashes['sha256']
        )
        
        db.session.add(new_file)
        db.session.commit()
        
        # Return file information
        return jsonify({
            'id': str(new_file.id),
            'filename': new_file.filename,
            'file_size': new_file.file_size,
            'mime_type': new_file.mime_type,
            'hash_md5': new_file.hash_md5,
            'hash_sha1': new_file.hash_sha1,
            'hash_sha256': new_file.hash_sha256,
            'upload_date': new_file.upload_date.isoformat()
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Error uploading file: {str(e)}")
        return jsonify({'error': 'Failed to upload file'}), 500

@files_bp.route('/', methods=['GET'])
@jwt_required()
def get_files():
    """
    Get a list of files uploaded by the current user.
    
    Returns:
        JSON response with list of files
    """
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Get files for the current user
        files = File.query.filter_by(user_id=current_user_id).all()
        
        # Format response
        files_data = [{
            'id': str(file.id),
            'filename': file.filename,
            'file_size': file.file_size,
            'mime_type': file.mime_type,
            'hash_md5': file.hash_md5,
            'hash_sha1': file.hash_sha1,
            'hash_sha256': file.hash_sha256,
            'upload_date': file.upload_date.isoformat()
        } for file in files]
        
        return jsonify(files_data), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving files: {str(e)}")
        return jsonify({'error': 'Failed to retrieve files'}), 500

@files_bp.route('/<file_id>', methods=['GET'])
@jwt_required()
def get_file(file_id):
    """
    Get information about a specific file.
    
    Args:
        file_id: UUID of the file
        
    Returns:
        JSON response with file information
    """
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Get file for the current user
        file = File.query.filter_by(id=file_id, user_id=current_user_id).first()
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Format response
        file_data = {
            'id': str(file.id),
            'filename': file.filename,
            'file_size': file.file_size,
            'mime_type': file.mime_type,
            'hash_md5': file.hash_md5,
            'hash_sha1': file.hash_sha1,
            'hash_sha256': file.hash_sha256,
            'upload_date': file.upload_date.isoformat()
        }
        
        return jsonify(file_data), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving file: {str(e)}")
        return jsonify({'error': 'Failed to retrieve file'}), 500

@files_bp.route('/<file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    """
    Delete a file.
    
    Args:
        file_id: UUID of the file
        
    Returns:
        JSON response indicating success or failure
    """
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Get file for the current user
        file = File.query.filter_by(id=file_id, user_id=current_user_id).first()
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Delete the file from storage
        if os.path.exists(file.storage_path):
            os.remove(file.storage_path)
            
            # Try to remove the parent directory if it's empty
            parent_dir = os.path.dirname(file.storage_path)
            if os.path.exists(parent_dir) and not os.listdir(parent_dir):
                os.rmdir(parent_dir)
        
        # Delete the file record from the database
        db.session.delete(file)
        db.session.commit()
        
        return jsonify({'message': 'File deleted successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Error deleting file: {str(e)}")
        return jsonify({'error': 'Failed to delete file'}), 500