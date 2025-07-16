"""
Database configuration and initialization for the VirusTotal File Scanner application.
"""
import uuid
import datetime
import enum
from sqlalchemy.dialects.postgresql import UUID, JSON
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize SQLAlchemy and Migrate extensions
db = SQLAlchemy()
migrate = Migrate()


class ScanStatus(enum.Enum):
    """Enum for scan status values."""
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class User(db.Model):
    """User model for authentication and API key ownership."""
    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    api_keys = db.relationship('ApiKey', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    files = db.relationship('File', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'


class ApiKey(db.Model):
    """API Key model for storing VirusTotal API keys."""
    __tablename__ = 'api_keys'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    key_value = db.Column(db.String(128), nullable=False)  # Will be encrypted
    name = db.Column(db.String(64), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    scans = db.relationship('Scan', backref='api_key', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<ApiKey {self.name}>'


class File(db.Model):
    """File model for storing uploaded file information."""
    __tablename__ = 'files'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(128), nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)
    hash_md5 = db.Column(db.String(32), nullable=False, index=True)
    hash_sha1 = db.Column(db.String(40), nullable=False, index=True)
    hash_sha256 = db.Column(db.String(64), nullable=False, index=True)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Relationships
    scans = db.relationship('Scan', backref='file', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<File {self.filename}>'


class Scan(db.Model):
    """Scan model for storing file scan information."""
    __tablename__ = 'scans'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id = db.Column(UUID(as_uuid=True), db.ForeignKey('files.id'), nullable=False)
    api_key_id = db.Column(UUID(as_uuid=True), db.ForeignKey('api_keys.id'), nullable=False)
    vt_scan_id = db.Column(db.String(128), nullable=True)
    status = db.Column(db.Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    result_summary = db.Column(JSON, nullable=True)
    detection_ratio = db.Column(db.String(16), nullable=True)
    scan_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Relationships
    results = db.relationship('ScanResult', backref='scan', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Scan {self.id}>'


class ScanResult(db.Model):
    """ScanResult model for storing detailed scan results from different engines."""
    __tablename__ = 'scan_results'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = db.Column(UUID(as_uuid=True), db.ForeignKey('scans.id'), nullable=False)
    engine_name = db.Column(db.String(64), nullable=False)
    engine_version = db.Column(db.String(32), nullable=True)
    result = db.Column(db.String(128), nullable=True)
    category = db.Column(db.String(32), nullable=True)
    update_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<ScanResult {self.engine_name}>'