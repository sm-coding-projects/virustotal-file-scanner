"""
Additional tests for database models.
"""
import pytest
import uuid
import datetime
from backend.models.database import db, User, ApiKey, File, Scan, ScanResult, ScanStatus

def test_user_password_methods(app, db):
    """Test User model password methods."""
    with app.app_context():
        # Create a user with a password
        user = User(
            username='passworduser',
            email='password@example.com'
        )
        
        # Set password
        user.set_password('testpassword123')
        
        # Verify password hash was created
        assert user.password_hash is not None
        assert user.password_hash != 'testpassword123'  # Password should be hashed
        
        # Verify password check works
        assert user.check_password('testpassword123') is True
        assert user.check_password('wrongpassword') is False
        
        # Save to database
        db.session.add(user)
        db.session.commit()
        
        # Retrieve from database and check password
        retrieved_user = User.query.filter_by(username='passworduser').first()
        assert retrieved_user.check_password('testpassword123') is True

def test_api_key_encryption(app, db, test_user):
    """Test ApiKey model encryption methods."""
    with app.app_context():
        # Create an API key with encryption
        api_key = ApiKey(
            user_id=test_user.id,
            name='Encrypted Key'
        )
        
        # Set the key value with encryption
        plain_key = 'test-api-key-value-123'
        api_key.set_key_value(plain_key)
        
        # Verify key was encrypted
        assert api_key.key_value is not None
        assert api_key.key_value != plain_key  # Key should be encrypted
        
        # Save to database
        db.session.add(api_key)
        db.session.commit()
        
        # Retrieve from database and decrypt
        retrieved_key = ApiKey.query.filter_by(name='Encrypted Key').first()
        decrypted_key = retrieved_key.get_key_value()
        assert decrypted_key == plain_key

def test_file_hash_validation(app, db, test_user):
    """Test File model hash validation."""
    with app.app_context():
        # Create a file with invalid hash
        file = File(
            user_id=test_user.id,
            filename='test.txt',
            file_size=1024,
            mime_type='text/plain',
            storage_path='/tmp/test.txt',
            hash_md5='invalid',  # Invalid MD5 hash
            hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
            hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        
        # Validate should fail
        assert file.validate_hashes() is False
        
        # Fix the hash
        file.hash_md5 = 'd41d8cd98f00b204e9800998ecf8427e'
        assert file.validate_hashes() is True
        
        # Test with invalid SHA-1
        file.hash_sha1 = 'invalid'
        assert file.validate_hashes() is False
        
        # Fix the hash
        file.hash_sha1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        assert file.validate_hashes() is True
        
        # Test with invalid SHA-256
        file.hash_sha256 = 'invalid'
        assert file.validate_hashes() is False
        
        # Fix the hash
        file.hash_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        assert file.validate_hashes() is True

def test_scan_status_transitions(app, db, test_user):
    """Test Scan model status transitions."""
    with app.app_context():
        # Create dependencies
        api_key = ApiKey(
            user_id=test_user.id,
            key_value='encrypted_key',
            name='Test Key'
        )
        db.session.add(api_key)
        
        file = File(
            user_id=test_user.id,
            filename='test.txt',
            file_size=1024,
            mime_type='text/plain',
            storage_path='/tmp/test.txt',
            hash_md5='d41d8cd98f00b204e9800998ecf8427e',
            hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
            hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        db.session.add(file)
        db.session.commit()
        
        # Create a scan with initial status
        scan = Scan(
            file_id=file.id,
            api_key_id=api_key.id,
            vt_scan_id='vt_analysis_id',
            status=ScanStatus.PENDING
        )
        db.session.add(scan)
        db.session.commit()
        
        # Test status transitions
        scan.status = ScanStatus.SCANNING
        db.session.commit()
        
        retrieved_scan = Scan.query.get(scan.id)
        assert retrieved_scan.status == ScanStatus.SCANNING
        
        scan.status = ScanStatus.COMPLETED
        scan.detection_ratio = '5/70'
        scan.result_summary = {'status': 'completed', 'stats': {'malicious': 5}}
        db.session.commit()
        
        retrieved_scan = Scan.query.get(scan.id)
        assert retrieved_scan.status == ScanStatus.COMPLETED
        assert retrieved_scan.detection_ratio == '5/70'
        assert retrieved_scan.result_summary['stats']['malicious'] == 5
        
        # Test failed status
        scan.status = ScanStatus.FAILED
        scan.result_summary = {'status': 'failed', 'error': 'API error'}
        db.session.commit()
        
        retrieved_scan = Scan.query.get(scan.id)
        assert retrieved_scan.status == ScanStatus.FAILED
        assert retrieved_scan.result_summary['error'] == 'API error'

def test_scan_result_categories(app, db, test_user):
    """Test ScanResult model categories."""
    with app.app_context():
        # Create dependencies
        api_key = ApiKey(
            user_id=test_user.id,
            key_value='encrypted_key',
            name='Test Key'
        )
        db.session.add(api_key)
        
        file = File(
            user_id=test_user.id,
            filename='test.txt',
            file_size=1024,
            mime_type='text/plain',
            storage_path='/tmp/test.txt',
            hash_md5='d41d8cd98f00b204e9800998ecf8427e',
            hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
            hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        )
        db.session.add(file)
        
        scan = Scan(
            file_id=file.id,
            api_key_id=api_key.id,
            status=ScanStatus.COMPLETED
        )
        db.session.add(scan)
        db.session.commit()
        
        # Create scan results with different categories
        categories = ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout']
        results = []
        
        for i, category in enumerate(categories):
            result = ScanResult(
                scan_id=scan.id,
                engine_name=f'Engine{i+1}',
                engine_version=f'{i+1}.0',
                result=f'result-{category}',
                category=category,
                update_date=datetime.datetime.utcnow()
            )
            results.append(result)
        
        db.session.add_all(results)
        db.session.commit()
        
        # Query by category
        for category in categories:
            category_results = ScanResult.query.filter_by(
                scan_id=scan.id, 
                category=category
            ).all()
            assert len(category_results) == 1
            assert category_results[0].category == category
        
        # Query malicious and suspicious together
        threat_results = ScanResult.query.filter(
            ScanResult.scan_id == scan.id,
            ScanResult.category.in_(['malicious', 'suspicious'])
        ).all()
        assert len(threat_results) == 2
        assert set([r.category for r in threat_results]) == set(['malicious', 'suspicious'])