"""
File upload and management API for the VirusTotal File Scanner application.
"""
import os
import hashlib
import uuid
import re
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from backend.models.database import db, File, User, ApiKey
from backend.utils.security import sanitize_input, validate_uuid, rate_limit, validate_content_type

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
@rate_limit(requests_per_minute=10)  # Limit file uploads to 10 per minute
@validate_content_type('multipart/form-data')
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
        
        # Get user's active API key for automatic scanning
        api_key = ApiKey.query.filter_by(user_id=user.id, is_active=True).first()
        
        # Prepare response data
        response_data = {
            'id': str(new_file.id),
            'filename': new_file.filename,
            'file_size': new_file.file_size,
            'mime_type': new_file.mime_type,
            'hash_md5': new_file.hash_md5,
            'hash_sha1': new_file.hash_sha1,
            'hash_sha256': new_file.hash_sha256,
            'upload_date': new_file.upload_date.isoformat()
        }
        
        # Automatically initiate a scan if an API key is available
        if api_key:
            try:
                # Import here to avoid circular imports
                from backend.models.database import Scan, ScanStatus
                from backend.services.virustotal import VirusTotalService
                
                # Create a new scan record
                new_scan = Scan(
                    file_id=new_file.id,
                    api_key_id=api_key.id,
                    status=ScanStatus.PENDING
                )
                
                db.session.add(new_scan)
                db.session.commit()
                
                # Initialize VirusTotal service with the API key
                vt_service = VirusTotalService(api_key.key_value)
                
                # Update scan status to scanning
                new_scan.status = ScanStatus.SCANNING
                db.session.commit()
                
                # Try to get existing report by hash first
                success, error, report_data = vt_service.get_file_report_by_hash(new_file.hash_sha256)
                
                if success:
                    # Request a fresh analysis
                    rescan_success, rescan_error, rescan_data = vt_service.rescan_file(new_file.hash_sha256)
                    
                    if rescan_success:
                        # Get the analysis ID
                        analysis_id = rescan_data.get('data', {}).get('id')
                        if analysis_id:
                            new_scan.vt_scan_id = analysis_id
                            db.session.commit()
                            
                            response_data['scan'] = {
                                'scan_id': str(new_scan.id),
                                'status': new_scan.status.value,
                                'message': 'Scan initiated automatically'
                            }
                        else:
                            new_scan.status = ScanStatus.FAILED
                            db.session.commit()
                            response_data['scan'] = {
                                'error': 'Failed to get analysis ID from VirusTotal',
                                'status': 'failed'
                            }
                    else:
                        new_scan.status = ScanStatus.FAILED
                        db.session.commit()
                        response_data['scan'] = {
                            'error': f'Failed to rescan file: {rescan_error}',
                            'status': 'failed'
                        }
                else:
                    # Upload the file to VirusTotal
                    scan_success, scan_error, scan_data = vt_service.scan_file(new_file.storage_path)
                    
                    if scan_success:
                        # Get the analysis ID
                        analysis_id = scan_data.get('data', {}).get('id')
                        if analysis_id:
                            new_scan.vt_scan_id = analysis_id
                            db.session.commit()
                            
                            response_data['scan'] = {
                                'scan_id': str(new_scan.id),
                                'status': new_scan.status.value,
                                'message': 'Scan initiated automatically'
                            }
                        else:
                            new_scan.status = ScanStatus.FAILED
                            db.session.commit()
                            response_data['scan'] = {
                                'error': 'Failed to get analysis ID from VirusTotal',
                                'status': 'failed'
                            }
                    else:
                        new_scan.status = ScanStatus.FAILED
                        db.session.commit()
                        response_data['scan'] = {
                            'error': f'Failed to scan file: {scan_error}',
                            'status': 'failed'
                        }
            except Exception as e:
                current_app.logger.error(f"Error initiating automatic scan: {str(e)}")
                response_data['scan'] = {
                    'error': 'Failed to initiate automatic scan',
                    'message': str(e),
                    'status': 'failed'
                }
        else:
            response_data['scan'] = {
                'message': 'No active API key found for automatic scanning',
                'status': 'pending'
            }
        
        # Return file information with scan status
        return jsonify(response_data), 201
        
    except Exception as e:
        current_app.logger.error(f"Error uploading file: {str(e)}")
        return jsonify({'error': 'Failed to upload file'}), 500

@files_bp.route('/', methods=['GET'])
@jwt_required()
@rate_limit(requests_per_minute=30)  # Limit file listing to 30 requests per minute
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
@rate_limit(requests_per_minute=30)
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
@rate_limit(requests_per_minute=10)
def delete_file(file_id):
    """
    Delete a file.
    
    Args:
        file_id: UUID of the file
        
    Returns:
        JSON response indicating success or failure
    """
    # Validate UUID format
    if not validate_uuid(file_id):
        return jsonify({'error': 'Invalid file ID format'}), 400
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