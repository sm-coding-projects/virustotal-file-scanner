"""
Pytest configuration for VirusTotal File Scanner tests.
"""
import json
import pytest
import uuid
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token
from backend.app import create_app
from backend.config.config import TestingConfig
from backend.models.database import db as _db, User

@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = create_app(TestingConfig)
    app.config.update({
        'TESTING': True,
    })
    
    # Create application context
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def db(app):
    """Database for testing."""
    return _db

@pytest.fixture
def test_user(app, db):
    """Create a test user."""
    user = User(
        id=uuid.uuid4(),
        username='testuser',
        email='test@example.com',
        password_hash=generate_password_hash('password123'),
        is_admin=False
    )
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def auth_headers(app, test_user):
    """Generate authentication headers for the test user."""
    with app.app_context():
        access_token = create_access_token(identity=str(test_user.id))
        return {'Authorization': f'Bearer {access_token}'}

@pytest.fixture
def register_user(client):
    """Register a new user for testing."""
    def _register_user(username='newuser', email='new@example.com', password='password123'):
        return client.post(
            '/api/auth/register',
            json={
                'username': username,
                'email': email,
                'password': password
            }
        )
    return _register_user

@pytest.fixture
def login_user(client):
    """Login a user for testing."""
    def _login_user(username='testuser', password='password123'):
        response = client.post(
            '/api/auth/login',
            json={
                'username': username,
                'password': password
            }
        )
        return json.loads(response.data)
    return _login_user