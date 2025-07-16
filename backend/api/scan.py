"""
Scan API for the VirusTotal File Scanner application.
"""
import datetime
import csv
import io
import json
import re
from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import desc, asc
from backend.models.database import db, File, ApiKey, Scan, ScanResult, ScanStatus, User
from backend.services.virustotal import VirusTotalService
from backend.utils.security import sanitize_input, sanitize_dict, validate_uuid, rate_limit, validate_content_type

# Create blueprint for scan operations
scan_bp = Blueprint('scan', __name__, url_prefix='/api/scan')

@scan_bp.route('/file/<file_id>', methods=['POST'])
@jwt_required()
@rate_limit(requests_per_minute=5)  # Limit scanning to 5 requests per minute
@validate_content_type()
def scan_file(file_id):
    """
    Scan a file using VirusTotal API.
    
    Args:
        file_id: UUID of the file to scan
        
    Returns:
        JSON response with scan information or error message
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
        
        # Get API key from request or use default
        api_key_id = request.json.get('api_key_id') if request.is_json else None
        
        # If no API key provided, get the user's default API key
        if not api_key_id:
            api_key = ApiKey.query.filter_by(user_id=current_user_id, is_active=True).first()
            if not api_key:
                return jsonify({'error': 'No active API key found'}), 400
        else:
            # Get the specified API key
            api_key = ApiKey.query.filter_by(id=api_key_id, user_id=current_user_id).first()
            if not api_key:
                return jsonify({'error': 'API key not found'}), 404
            
            if not api_key.is_active:
                return jsonify({'error': 'API key is not active'}), 400
        
        # Check if the file has already been scanned with this API key
        existing_scan = Scan.query.filter_by(
            file_id=file.id, 
            api_key_id=api_key.id,
            status=ScanStatus.COMPLETED
        ).first()
        
        if existing_scan:
            return jsonify({
                'message': 'File has already been scanned',
                'scan_id': str(existing_scan.id),
                'status': existing_scan.status.value,
                'detection_ratio': existing_scan.detection_ratio,
                'scan_date': existing_scan.scan_date.isoformat()
            }), 200
        
        # Create a new scan record
        new_scan = Scan(
            file_id=file.id,
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
        success, error, report_data = vt_service.get_file_report_by_hash(file.hash_sha256)
        
        if success:
            # File already exists in VirusTotal database
            current_app.logger.info(f"File {file.id} found in VirusTotal database")
            
            # Request a fresh analysis
            rescan_success, rescan_error, rescan_data = vt_service.rescan_file(file.hash_sha256)
            
            if rescan_success:
                # Get the analysis ID
                analysis_id = rescan_data.get('data', {}).get('id')
                if analysis_id:
                    new_scan.vt_scan_id = analysis_id
                    db.session.commit()
                    
                    return jsonify({
                        'message': 'Scan initiated successfully',
                        'scan_id': str(new_scan.id),
                        'status': new_scan.status.value
                    }), 202
                else:
                    new_scan.status = ScanStatus.FAILED
                    db.session.commit()
                    return jsonify({'error': 'Failed to get analysis ID from VirusTotal'}), 500
            else:
                # If rescan fails but we have a report, use the existing report
                current_app.logger.warning(f"Rescan failed for file {file.id}: {rescan_error}")
                
                # Process the existing report
                return process_existing_report(vt_service, report_data, new_scan, file)
        else:
            # File not found in VirusTotal, upload it for scanning
            current_app.logger.info(f"File {file.id} not found in VirusTotal database, uploading for scanning")
            
            # Upload the file to VirusTotal
            scan_success, scan_error, scan_data = vt_service.scan_file(file.storage_path)
            
            if scan_success:
                # Get the analysis ID
                analysis_id = scan_data.get('data', {}).get('id')
                if analysis_id:
                    new_scan.vt_scan_id = analysis_id
                    db.session.commit()
                    
                    return jsonify({
                        'message': 'Scan initiated successfully',
                        'scan_id': str(new_scan.id),
                        'status': new_scan.status.value
                    }), 202
                else:
                    new_scan.status = ScanStatus.FAILED
                    db.session.commit()
                    return jsonify({'error': 'Failed to get analysis ID from VirusTotal'}), 500
            else:
                new_scan.status = ScanStatus.FAILED
                db.session.commit()
                return jsonify({'error': f'Failed to scan file: {scan_error}'}), 500
                
    except Exception as e:
        current_app.logger.error(f"Error scanning file: {str(e)}")
        return jsonify({'error': 'Failed to scan file'}), 500

def process_existing_report(vt_service, report_data, scan, file):
    """
    Process an existing VirusTotal report.
    
    Args:
        vt_service: VirusTotal service instance
        report_data: Report data from VirusTotal
        scan: Scan database record
        file: File database record
        
    Returns:
        JSON response with scan information
    """
    try:
        # Get the last analysis results
        last_analysis_results = report_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
        last_analysis_date = report_data.get('data', {}).get('attributes', {}).get('last_analysis_date')
        
        if last_analysis_results:
            # Create a mock analysis data structure for parsing
            mock_analysis_data = {
                'data': {
                    'attributes': {
                        'status': 'completed',
                        'stats': report_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}),
                        'results': last_analysis_results,
                        'date': last_analysis_date
                    }
                }
            }
            
            # Parse the results
            results_summary = vt_service.parse_scan_results(mock_analysis_data)
            
            # Update the scan record
            scan.status = ScanStatus.COMPLETED
            scan.result_summary = results_summary
            scan.detection_ratio = results_summary.get('detection_ratio', '0/0')
            if last_analysis_date:
                scan.scan_date = datetime.datetime.fromtimestamp(last_analysis_date)
            
            # Save the scan results
            save_scan_results(scan, results_summary.get('engine_results', []))
            
            return jsonify({
                'message': 'Scan completed successfully',
                'scan_id': str(scan.id),
                'status': scan.status.value,
                'detection_ratio': scan.detection_ratio,
                'scan_date': scan.scan_date.isoformat()
            }), 200
        else:
            scan.status = ScanStatus.FAILED
            db.session.commit()
            return jsonify({'error': 'No analysis results found in VirusTotal report'}), 500
            
    except Exception as e:
        current_app.logger.error(f"Error processing existing report: {str(e)}")
        scan.status = ScanStatus.FAILED
        db.session.commit()
        return jsonify({'error': 'Failed to process scan results'}), 500

@scan_bp.route('/<scan_id>/status', methods=['GET'])
@jwt_required()
@rate_limit(requests_per_minute=30)
def get_scan_status(scan_id):
    """
    Get the status of a scan.
    
    Args:
        scan_id: UUID of the scan
        
    Returns:
        JSON response with scan status information
    """
    # Validate UUID format
    if not validate_uuid(scan_id):
        return jsonify({'error': 'Invalid scan ID format'}), 400
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Get the scan
        scan = Scan.query.join(File).filter(
            Scan.id == scan_id,
            File.user_id == current_user_id
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # If scan is already completed or failed, return the status
        if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
            return jsonify({
                'scan_id': str(scan.id),
                'status': scan.status.value,
                'detection_ratio': scan.detection_ratio,
                'scan_date': scan.scan_date.isoformat() if scan.scan_date else None
            }), 200
        
        # If scan is pending or scanning, check the status from VirusTotal
        if scan.vt_scan_id:
            # Get the API key
            api_key = ApiKey.query.filter_by(id=scan.api_key_id).first()
            
            if not api_key:
                return jsonify({'error': 'API key not found'}), 404
            
            # Initialize VirusTotal service with the API key
            vt_service = VirusTotalService(api_key.key_value)
            
            # Check the analysis status
            success, error, analysis_data = vt_service.get_analysis_status(scan.vt_scan_id)
            
            if success:
                # Get the analysis status
                analysis_status = analysis_data.get('data', {}).get('attributes', {}).get('status')
                
                if analysis_status == 'completed':
                    # Parse the results
                    results_summary = vt_service.parse_scan_results(analysis_data)
                    
                    # Update the scan record
                    scan.status = ScanStatus.COMPLETED
                    scan.result_summary = results_summary
                    scan.detection_ratio = results_summary.get('detection_ratio', '0/0')
                    scan_date = results_summary.get('scan_date')
                    if scan_date:
                        try:
                            scan.scan_date = datetime.datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            scan.scan_date = datetime.datetime.utcnow()
                    
                    # Save the scan results
                    save_scan_results(scan, results_summary.get('engine_results', []))
                    
                    return jsonify({
                        'scan_id': str(scan.id),
                        'status': scan.status.value,
                        'detection_ratio': scan.detection_ratio,
                        'scan_date': scan.scan_date.isoformat()
                    }), 200
                elif analysis_status == 'failed':
                    scan.status = ScanStatus.FAILED
                    db.session.commit()
                    return jsonify({
                        'scan_id': str(scan.id),
                        'status': scan.status.value,
                        'error': 'VirusTotal analysis failed'
                    }), 200
                else:
                    # Analysis is still in progress
                    return jsonify({
                        'scan_id': str(scan.id),
                        'status': scan.status.value,
                        'message': 'Scan is still in progress'
                    }), 200
            else:
                return jsonify({'error': f'Failed to check scan status: {error}'}), 500
        else:
            return jsonify({
                'scan_id': str(scan.id),
                'status': scan.status.value,
                'message': 'Scan is pending'
            }), 200
            
    except Exception as e:
        current_app.logger.error(f"Error checking scan status: {str(e)}")
        return jsonify({'error': 'Failed to check scan status'}), 500

def save_scan_results(scan, engine_results):
    """
    Save scan results to the database.
    
    Args:
        scan: Scan database record
        engine_results: List of engine results from VirusTotal
    """
    try:
        # Delete any existing results for this scan
        ScanResult.query.filter_by(scan_id=scan.id).delete()
        
        # Add new results
        for result in engine_results:
            scan_result = ScanResult(
                scan_id=scan.id,
                engine_name=result.get('engine_name', ''),
                engine_version=result.get('engine_version', ''),
                result=result.get('result', ''),
                category=result.get('category', ''),
                update_date=datetime.datetime.utcnow()  # Use current time as fallback
            )
            
            # Try to parse the update date if available
            update_date = result.get('update_date')
            if update_date:
                try:
                    scan_result.update_date = datetime.datetime.fromisoformat(update_date.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    pass  # Keep the default value
            
            db.session.add(scan_result)
        
        db.session.commit()
        
    except Exception as e:
        current_app.logger.error(f"Error saving scan results: {str(e)}")
        db.session.rollback()
        raise

@scan_bp.route('/<scan_id>/results', methods=['GET'])
@jwt_required()
@rate_limit(requests_per_minute=30)
def get_scan_results(scan_id):
    """
    Get the results of a scan.
    
    Args:
        scan_id: UUID of the scan
        
    Returns:
        JSON response with scan results
    """
    # Validate UUID format
    if not validate_uuid(scan_id):
        return jsonify({'error': 'Invalid scan ID format'}), 400
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Get the scan
        scan = Scan.query.join(File).filter(
            Scan.id == scan_id,
            File.user_id == current_user_id
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get the file
        file = File.query.filter_by(id=scan.file_id).first()
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # If scan is not completed, return the status
        if scan.status != ScanStatus.COMPLETED:
            return jsonify({
                'scan_id': str(scan.id),
                'status': scan.status.value,
                'message': 'Scan results not available yet'
            }), 200
        
        # Get the scan results
        results = ScanResult.query.filter_by(scan_id=scan.id).all()
        
        # Format the results
        results_data = [{
            'engine_name': result.engine_name,
            'engine_version': result.engine_version,
            'result': result.result,
            'category': result.category,
            'update_date': result.update_date.isoformat() if result.update_date else None
        } for result in results]
        
        # Return the scan results
        return jsonify({
            'scan_id': str(scan.id),
            'file_id': str(file.id),
            'filename': file.filename,
            'status': scan.status.value,
            'detection_ratio': scan.detection_ratio,
            'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
            'results': results_data,
            'summary': scan.result_summary
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting scan results: {str(e)}")
        return jsonify({'error': 'Failed to get scan results'}), 500

@scan_bp.route('/file/<file_id>/rescan', methods=['POST'])
@jwt_required()
@rate_limit(requests_per_minute=5)  # Limit rescanning to 5 requests per minute
@validate_content_type()
def rescan_file(file_id):
    """
    Rescan a previously scanned file.
    
    Args:
        file_id: UUID of the file to rescan
        
    Returns:
        JSON response with scan information or error message
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
        
        # Get API key from request or use default
        api_key_id = request.json.get('api_key_id') if request.is_json else None
        
        # If no API key provided, get the user's default API key
        if not api_key_id:
            api_key = ApiKey.query.filter_by(user_id=current_user_id, is_active=True).first()
            if not api_key:
                return jsonify({'error': 'No active API key found'}), 400
        else:
            # Get the specified API key
            api_key = ApiKey.query.filter_by(id=api_key_id, user_id=current_user_id).first()
            if not api_key:
                return jsonify({'error': 'API key not found'}), 404
            
            if not api_key.is_active:
                return jsonify({'error': 'API key is not active'}), 400
        
        # Create a new scan record
        new_scan = Scan(
            file_id=file.id,
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
        
        # Request a rescan from VirusTotal
        success, error, rescan_data = vt_service.rescan_file(file.hash_sha256)
        
        if success:
            # Get the analysis ID
            analysis_id = rescan_data.get('data', {}).get('id')
            if analysis_id:
                new_scan.vt_scan_id = analysis_id
                db.session.commit()
                
                return jsonify({
                    'message': 'Rescan initiated successfully',
                    'scan_id': str(new_scan.id),
                    'status': new_scan.status.value
                }), 202
            else:
                new_scan.status = ScanStatus.FAILED
                db.session.commit()
                return jsonify({'error': 'Failed to get analysis ID from VirusTotal'}), 500
        else:
            # If rescan fails, try uploading the file again
            scan_success, scan_error, scan_data = vt_service.scan_file(file.storage_path)
            
            if scan_success:
                # Get the analysis ID
                analysis_id = scan_data.get('data', {}).get('id')
                if analysis_id:
                    new_scan.vt_scan_id = analysis_id
                    db.session.commit()
                    
                    return jsonify({
                        'message': 'Scan initiated successfully',
                        'scan_id': str(new_scan.id),
                        'status': new_scan.status.value
                    }), 202
                else:
                    new_scan.status = ScanStatus.FAILED
                    db.session.commit()
                    return jsonify({'error': 'Failed to get analysis ID from VirusTotal'}), 500
            else:
                new_scan.status = ScanStatus.FAILED
                db.session.commit()
                return jsonify({'error': f'Failed to scan file: {scan_error}'}), 500
                
    except Exception as e:
        current_app.logger.error(f"Error rescanning file: {str(e)}")
        return jsonify({'error': 'Failed to rescan file'}), 500

@scan_bp.route('/user/<user_id>', methods=['GET'])
@jwt_required()
@rate_limit(requests_per_minute=30)
def get_user_scans(user_id):
    """
    Get all scans for a user.
    
    Args:
        user_id: UUID of the user
        
    Returns:
        JSON response with list of scans
    """
    # Validate UUID format
    if not validate_uuid(user_id):
        return jsonify({'error': 'Invalid user ID format'}), 400
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Check if the user is requesting their own scans or is an admin
        user = User.query.filter_by(id=current_user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if str(current_user_id) != user_id and not user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get all scans for the user
        scans = Scan.query.join(File).filter(File.user_id == user_id).all()
        
        # Format the scans
        scans_data = [{
            'id': str(scan.id),
            'file_id': str(scan.file_id),
            'status': scan.status.value,
            'detection_ratio': scan.detection_ratio,
            'scan_date': scan.scan_date.isoformat() if scan.scan_date else None
        } for scan in scans]
        
        return jsonify(scans_data), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting user scans: {str(e)}")
        return jsonify({'error': 'Failed to get user scans'}), 500

@scan_bp.route('/file/<file_id>', methods=['GET'])
@jwt_required()
@rate_limit(requests_per_minute=30)
def get_file_scans(file_id):
    """
    Get all scans for a file.
    
    Args:
        file_id: UUID of the file
        
    Returns:
        JSON response with list of scans
    """
    # Validate UUID format
    if not validate_uuid(file_id):
        return jsonify({'error': 'Invalid file ID format'}), 400
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Check if the file belongs to the user
        file = File.query.filter_by(id=file_id, user_id=current_user_id).first()
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Get all scans for the file
        scans = Scan.query.filter_by(file_id=file_id).all()
        
        # Format the scans
        scans_data = [{
            'id': str(scan.id),
            'status': scan.status.value,
            'detection_ratio': scan.detection_ratio,
            'scan_date': scan.scan_date.isoformat() if scan.scan_date else None
        } for scan in scans]
        
        return jsonify(scans_data), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting file scans: {str(e)}")
        return jsonify({'error': 'Failed to get file scans'}), 500

@scan_bp.route('/results', methods=['GET'])
@jwt_required()
@rate_limit(requests_per_minute=20)
def get_all_scan_results():
    """
    Get all scan results with filtering and sorting options.
    
    Query parameters:
        status: Filter by scan status (completed, failed, pending, scanning)
        detection_min: Filter by minimum detection ratio (e.g., 1)
        detection_max: Filter by maximum detection ratio (e.g., 10)
        date_from: Filter by scan date from (ISO format)
        date_to: Filter by scan date to (ISO format)
        sort_by: Field to sort by (scan_date, detection_ratio)
        sort_order: Sort order (asc, desc)
        page: Page number for pagination
        per_page: Number of results per page
        
    Returns:
        JSON response with paginated scan results
    """
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Start building the query
        query = Scan.query.join(File).filter(File.user_id == current_user_id)
        
        # Apply filters
        status = request.args.get('status')
        if status:
            try:
                scan_status = ScanStatus[status.upper()]
                query = query.filter(Scan.status == scan_status)
            except KeyError:
                return jsonify({'error': f'Invalid status: {status}'}), 400
        
        detection_min = request.args.get('detection_min')
        if detection_min:
            try:
                # Extract the numerator from the detection ratio (e.g., "5/70" -> 5)
                query = query.filter(db.func.cast(db.func.split_part(Scan.detection_ratio, '/', 1), db.Integer) >= int(detection_min))
            except ValueError:
                return jsonify({'error': f'Invalid detection_min: {detection_min}'}), 400
        
        detection_max = request.args.get('detection_max')
        if detection_max:
            try:
                # Extract the numerator from the detection ratio (e.g., "5/70" -> 5)
                query = query.filter(db.func.cast(db.func.split_part(Scan.detection_ratio, '/', 1), db.Integer) <= int(detection_max))
            except ValueError:
                return jsonify({'error': f'Invalid detection_max: {detection_max}'}), 400
        
        date_from = request.args.get('date_from')
        if date_from:
            try:
                from_date = datetime.datetime.fromisoformat(date_from)
                query = query.filter(Scan.scan_date >= from_date)
            except ValueError:
                return jsonify({'error': f'Invalid date_from format: {date_from}. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}), 400
        
        date_to = request.args.get('date_to')
        if date_to:
            try:
                to_date = datetime.datetime.fromisoformat(date_to)
                query = query.filter(Scan.scan_date <= to_date)
            except ValueError:
                return jsonify({'error': f'Invalid date_to format: {date_to}. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}), 400
        
        # Apply sorting
        sort_by = request.args.get('sort_by', 'scan_date')
        sort_order = request.args.get('sort_order', 'desc')
        
        if sort_by == 'scan_date':
            if sort_order == 'asc':
                query = query.order_by(asc(Scan.scan_date))
            else:
                query = query.order_by(desc(Scan.scan_date))
        elif sort_by == 'detection_ratio':
            # Sort by the numerator of the detection ratio
            if sort_order == 'asc':
                query = query.order_by(asc(db.func.cast(db.func.split_part(Scan.detection_ratio, '/', 1), db.Integer)))
            else:
                query = query.order_by(desc(db.func.cast(db.func.split_part(Scan.detection_ratio, '/', 1), db.Integer)))
        else:
            return jsonify({'error': f'Invalid sort_by parameter: {sort_by}'}), 400
        
        # Apply pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Limit per_page to a reasonable value
        if per_page > 100:
            per_page = 100
        
        # Execute the query with pagination
        paginated_scans = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Format the results
        scans_data = []
        for scan in paginated_scans.items:
            file = File.query.filter_by(id=scan.file_id).first()
            
            scan_data = {
                'id': str(scan.id),
                'file_id': str(scan.file_id),
                'filename': file.filename if file else 'Unknown',
                'status': scan.status.value,
                'detection_ratio': scan.detection_ratio,
                'scan_date': scan.scan_date.isoformat() if scan.scan_date else None
            }
            
            scans_data.append(scan_data)
        
        # Prepare pagination metadata
        pagination = {
            'page': page,
            'per_page': per_page,
            'total_pages': paginated_scans.pages,
            'total_items': paginated_scans.total
        }
        
        return jsonify({
            'scans': scans_data,
            'pagination': pagination
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting scan results: {str(e)}")
        return jsonify({'error': 'Failed to get scan results'}), 500

@scan_bp.route('/<scan_id>/export', methods=['GET'])
@jwt_required()
def export_scan_results(scan_id):
    """
    Export scan results in various formats.
    
    Args:
        scan_id: UUID of the scan
        
    Query parameters:
        format: Export format (csv, json)
        
    Returns:
        File download response
    """
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Get the scan
        scan = Scan.query.join(File).filter(
            Scan.id == scan_id,
            File.user_id == current_user_id
        ).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get the file
        file = File.query.filter_by(id=scan.file_id).first()
        
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # If scan is not completed, return an error
        if scan.status != ScanStatus.COMPLETED:
            return jsonify({
                'error': 'Scan results not available yet',
                'status': scan.status.value
            }), 400
        
        # Get the scan results
        results = ScanResult.query.filter_by(scan_id=scan.id).all()
        
        # Format the results
        results_data = [{
            'engine_name': result.engine_name,
            'engine_version': result.engine_version,
            'result': result.result,
            'category': result.category,
            'update_date': result.update_date.isoformat() if result.update_date else None
        } for result in results]
        
        # Get the export format
        export_format = request.args.get('format', 'csv').lower()
        
        if export_format == 'csv':
            # Create a CSV file in memory
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Engine Name', 'Engine Version', 'Result', 'Category', 'Update Date'])
            
            # Write data
            for result in results_data:
                writer.writerow([
                    result['engine_name'],
                    result['engine_version'],
                    result['result'],
                    result['category'],
                    result['update_date']
                ])
            
            # Prepare the response
            output.seek(0)
            filename = f"scan_results_{file.filename}_{scan.scan_date.strftime('%Y%m%d')}.csv"
            
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=filename
            )
            
        elif export_format == 'json':
            # Create a JSON export
            export_data = {
                'scan_id': str(scan.id),
                'file_id': str(file.id),
                'filename': file.filename,
                'file_hash_md5': file.hash_md5,
                'file_hash_sha1': file.hash_sha1,
                'file_hash_sha256': file.hash_sha256,
                'status': scan.status.value,
                'detection_ratio': scan.detection_ratio,
                'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
                'results': results_data,
                'summary': scan.result_summary
            }
            
            # Prepare the response
            filename = f"scan_results_{file.filename}_{scan.scan_date.strftime('%Y%m%d')}.json"
            
            return send_file(
                io.BytesIO(json.dumps(export_data, indent=2).encode('utf-8')),
                mimetype='application/json',
                as_attachment=True,
                download_name=filename
            )
            
        else:
            return jsonify({'error': f'Unsupported export format: {export_format}'}), 400
            
    except Exception as e:
        current_app.logger.error(f"Error exporting scan results: {str(e)}")
        return jsonify({'error': 'Failed to export scan results'}), 500

@scan_bp.route('/results/export', methods=['GET'])
@jwt_required()
def export_all_scan_results():
    """
    Export all scan results with filtering options.
    
    Query parameters:
        status: Filter by scan status (completed, failed, pending, scanning)
        detection_min: Filter by minimum detection ratio (e.g., 1)
        detection_max: Filter by maximum detection ratio (e.g., 10)
        date_from: Filter by scan date from (ISO format)
        date_to: Filter by scan date to (ISO format)
        format: Export format (csv, json)
        
    Returns:
        File download response
    """
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Start building the query
        query = Scan.query.join(File).filter(File.user_id == current_user_id)
        
        # Apply filters
        status = request.args.get('status')
        if status:
            try:
                scan_status = ScanStatus[status.upper()]
                query = query.filter(Scan.status == scan_status)
            except KeyError:
                return jsonify({'error': f'Invalid status: {status}'}), 400
        
        detection_min = request.args.get('detection_min')
        if detection_min:
            try:
                # Extract the numerator from the detection ratio (e.g., "5/70" -> 5)
                query = query.filter(db.func.cast(db.func.split_part(Scan.detection_ratio, '/', 1), db.Integer) >= int(detection_min))
            except ValueError:
                return jsonify({'error': f'Invalid detection_min: {detection_min}'}), 400
        
        detection_max = request.args.get('detection_max')
        if detection_max:
            try:
                # Extract the numerator from the detection ratio (e.g., "5/70" -> 5)
                query = query.filter(db.func.cast(db.func.split_part(Scan.detection_ratio, '/', 1), db.Integer) <= int(detection_max))
            except ValueError:
                return jsonify({'error': f'Invalid detection_max: {detection_max}'}), 400
        
        date_from = request.args.get('date_from')
        if date_from:
            try:
                from_date = datetime.datetime.fromisoformat(date_from)
                query = query.filter(Scan.scan_date >= from_date)
            except ValueError:
                return jsonify({'error': f'Invalid date_from format: {date_from}. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}), 400
        
        date_to = request.args.get('date_to')
        if date_to:
            try:
                to_date = datetime.datetime.fromisoformat(date_to)
                query = query.filter(Scan.scan_date <= to_date)
            except ValueError:
                return jsonify({'error': f'Invalid date_to format: {date_to}. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}), 400
        
        # Execute the query
        scans = query.all()
        
        # Get the export format
        export_format = request.args.get('format', 'csv').lower()
        
        if export_format == 'csv':
            # Create a CSV file in memory
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Scan ID', 'File Name', 'File Hash (SHA256)', 'Detection Ratio', 'Scan Date', 'Status'])
            
            # Write data
            for scan in scans:
                file = File.query.filter_by(id=scan.file_id).first()
                writer.writerow([
                    str(scan.id),
                    file.filename if file else 'Unknown',
                    file.hash_sha256 if file else 'Unknown',
                    scan.detection_ratio,
                    scan.scan_date.isoformat() if scan.scan_date else 'N/A',
                    scan.status.value
                ])
            
            # Prepare the response
            output.seek(0)
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"all_scan_results_{timestamp}.csv"
            
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=filename
            )
            
        elif export_format == 'json':
            # Create a JSON export
            export_data = []
            
            for scan in scans:
                file = File.query.filter_by(id=scan.file_id).first()
                
                scan_data = {
                    'scan_id': str(scan.id),
                    'file_id': str(scan.file_id) if file else None,
                    'filename': file.filename if file else 'Unknown',
                    'file_hash_sha256': file.hash_sha256 if file else 'Unknown',
                    'status': scan.status.value,
                    'detection_ratio': scan.detection_ratio,
                    'scan_date': scan.scan_date.isoformat() if scan.scan_date else None
                }
                
                export_data.append(scan_data)
            
            # Prepare the response
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"all_scan_results_{timestamp}.json"
            
            return send_file(
                io.BytesIO(json.dumps(export_data, indent=2).encode('utf-8')),
                mimetype='application/json',
                as_attachment=True,
                download_name=filename
            )
            
        else:
            return jsonify({'error': f'Unsupported export format: {export_format}'}), 400
            
    except Exception as e:
        current_app.logger.error(f"Error exporting all scan results: {str(e)}")
        return jsonify({'error': 'Failed to export scan results'}), 500