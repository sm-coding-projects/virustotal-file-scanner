"""
Pytest configuration for VirusTotal File Scanner tests.
"""
import pytest
from backend.app import create_app
from backend.config.config import TestingConfig
from backend.models.database import db as _db

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