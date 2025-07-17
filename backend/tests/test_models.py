"""
Tests for database models.
"""
import pytest
import uuid
import datetime
from backend.models.database import db, User, ApiKey, File, Scan, ScanResult, ScanStatus


def test_user_model_creation(app, db):
    """Test User model creation and basic operations."""
    with app.app_context():
        # Create a user
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash='hashed_password',
            is_admin=False
        )
        
        # Save to database first to generate ID
        db.session.add(user)
        db.session.commit()
        
        # Test that ID is automatically generated
        assert user.id is not None
        assert isinstance(user.id, uuid.UUID)
        
        # Test string representation
        assert str(user) == '<User testuser>'
        
        # Retrieve from database
        retrieved_user = User.query.filter_by(username='testuser').first()
        assert retrieved_user is not None
        assert retrieved_user.username == 'testuser'
        assert retrieved_user.email == 'test@example.com'
        assert retrieved_user.is_admin is False
        assert isinstance(retrieved_user.created_at, datetime.datetime)
        assert isinstance(retrieved_user.updated_at, datetime.datetime)


def test_user_model_unique_constraints(app, db):
    """Test User model unique constraints."""
    with app.app_context():
        # Create first user
        user1 = User(
            username='testuser',
            email='test@example.com',
            password_hash='hashed_password'
        )
        db.session.add(user1)
        db.session.commit()
        
        # Try to create user with same username
        user2 = User(
            username='testuser',
            email='different@example.com',
            password_hash='hashed_password'
        )
        db.session.add(user2)
        
        with pytest.raises(Exception):  # Should raise IntegrityError
            db.session.commit()
        
        db.session.rollback()
        
        # Try to create user with same email
        user3 = User(
            username='differentuser',
            email='test@example.com',
            password_hash='hashed_password'
        )
        db.session.add(user3)
        
        with pytest.raises(Exception):  # Should raise IntegrityError
            db.session.commit()


def test_api_key_model_creation(app, db, test_user):
    """Test ApiKey model creation and relationships."""
    with app.app_context():
        # Create an API key
        api_key = ApiKey(
            user_id=test_user.id,
            key_value='encrypted_key_value',
            name='Test API Key',
            is_active=True
        )
        
        # Save to database first to generate ID
        db.session.add(api_key)
        db.session.commit()
        
        # Test that ID is automatically generated
        assert api_key.id is not None
        assert isinstance(api_key.id, uuid.UUID)
        
        # Test string representation
        assert str(api_key) == '<ApiKey Test API Key>'
        
        # Test relationship
        assert api_key.user == test_user
        assert api_key in test_user.api_keys
        
        # Retrieve from database
        retrieved_key = ApiKey.query.filter_by(name='Test API Key').first()
        assert retrieved_key is not None
        assert retrieved_key.user_id == test_user.id
        assert retrieved_key.key_value == 'encrypted_key_value'
        assert retrieved_key.is_active is True


def test_file_model_creation(app, db, test_user):
    """Test File model creation and relationships."""
    with app.app_context():
        # Create a file
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
        
        # Save to database first to generate ID
        db.session.add(file)
        db.session.commit()
        
        # Test that ID is automatically generated
        assert file.id is not None
        assert isinstance(file.id, uuid.UUID)
        
        # Test string representation
        assert str(file) == '<File test.txt>'
        
        # Test relationship
        assert file.user == test_user
        assert file in test_user.files
        
        # Retrieve from database
        retrieved_file = File.query.filter_by(filename='test.txt').first()
        assert retrieved_file is not None
        assert retrieved_file.user_id == test_user.id
        assert retrieved_file.file_size == 1024
        assert retrieved_file.mime_type == 'text/plain'
        assert retrieved_file.hash_md5 == 'd41d8cd98f00b204e9800998ecf8427e'


def test_scan_model_creation(app, db, test_user):
    """Test Scan model creation and relationships."""
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
        
        # Create a scan
        scan = Scan(
            file_id=file.id,
            api_key_id=api_key.id,
            vt_scan_id='vt_analysis_id',
            status=ScanStatus.PENDING,
            result_summary={'status': 'pending'},
            detection_ratio='0/0'
        )
        
        # Test that ID is automatically generated
        assert scan.id is not None
        assert isinstance(scan.id, uuid.UUID)
        
        # Test string representation
        assert str(scan).startswith('<Scan ')
        
        # Test enum status
        assert scan.status == ScanStatus.PENDING
        assert scan.status.value == 'pending'
        
        # Save to database
        db.session.add(scan)
        db.session.commit()
        
        # Test relationships
        assert scan.file == file
        assert scan.api_key == api_key
        assert scan in file.scans
        assert scan in api_key.scans
        
        # Test status updates
        scan.status = ScanStatus.COMPLETED
        db.session.commit()
        
        retrieved_scan = Scan.query.filter_by(vt_scan_id='vt_analysis_id').first()
        assert retrieved_scan.status == ScanStatus.COMPLETED


def test_scan_result_model_creation(app, db, test_user):
    """Test ScanResult model creation and relationships."""
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
        
        # Create scan results
        result1 = ScanResult(
            scan_id=scan.id,
            engine_name='Engine1',
            engine_version='1.0',
            result='clean',
            category='undetected',
            update_date=datetime.datetime.utcnow()
        )
        
        result2 = ScanResult(
            scan_id=scan.id,
            engine_name='Engine2',
            engine_version='2.0',
            result='malware',
            category='malicious',
            update_date=datetime.datetime.utcnow()
        )
        
        # Test that IDs are automatically generated
        assert result1.id is not None
        assert result2.id is not None
        
        # Test string representations
        assert str(result1) == '<ScanResult Engine1>'
        assert str(result2) == '<ScanResult Engine2>'
        
        # Save to database
        db.session.add_all([result1, result2])
        db.session.commit()
        
        # Test relationships
        assert result1.scan == scan
        assert result2.scan == scan
        assert result1 in scan.results
        assert result2 in scan.results
        
        # Test querying results
        results = ScanResult.query.filter_by(scan_id=scan.id).all()
        assert len(results) == 2
        
        malicious_results = ScanResult.query.filter_by(
            scan_id=scan.id, 
            category='malicious'
        ).all()
        assert len(malicious_results) == 1
        assert malicious_results[0].engine_name == 'Engine2'


def test_scan_status_enum(app):
    """Test ScanStatus enum values."""
    with app.app_context():
        # Test enum values
        assert ScanStatus.PENDING.value == 'pending'
        assert ScanStatus.SCANNING.value == 'scanning'
        assert ScanStatus.COMPLETED.value == 'completed'
        assert ScanStatus.FAILED.value == 'failed'
        
        # Test enum comparison
        assert ScanStatus.PENDING != ScanStatus.COMPLETED
        assert ScanStatus.SCANNING == ScanStatus.SCANNING


def test_model_cascade_deletion(app, db, test_user):
    """Test cascade deletion of related models."""
    with app.app_context():
        # Create a complete hierarchy
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
        
        result = ScanResult(
            scan_id=scan.id,
            engine_name='Engine1',
            engine_version='1.0',
            result='clean',
            category='undetected'
        )
        db.session.add(result)
        db.session.commit()
        
        # Store IDs for verification
        scan_id = scan.id
        result_id = result.id
        
        # Delete the file - should cascade to scan and scan results
        db.session.delete(file)
        db.session.commit()
        
        # Verify cascade deletion
        assert Scan.query.filter_by(id=scan_id).first() is None
        assert ScanResult.query.filter_by(id=result_id).first() is None
        
        # API key should still exist
        assert ApiKey.query.filter_by(id=api_key.id).first() is not None


def test_model_timestamps(app, db, test_user):
    """Test automatic timestamp handling."""
    with app.app_context():
        # Create a user
        user = User(
            username='timestampuser',
            email='timestamp@example.com',
            password_hash='hashed_password'
        )
        db.session.add(user)
        db.session.commit()
        
        # Check that timestamps were set
        assert user.created_at is not None
        assert user.updated_at is not None
        assert isinstance(user.created_at, datetime.datetime)
        assert isinstance(user.updated_at, datetime.datetime)
        
        # Store original timestamps
        original_created = user.created_at
        original_updated = user.updated_at
        
        # Update the user
        import time
        time.sleep(0.1)  # Small delay to ensure timestamp difference
        user.username = 'updateduser'
        db.session.commit()
        
        # Check that updated_at changed but created_at didn't
        assert user.created_at == original_created
        assert user.updated_at > original_updated