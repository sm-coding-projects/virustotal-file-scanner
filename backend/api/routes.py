"""
API routes configuration for the VirusTotal File Scanner application.
"""
from flask import Flask, Blueprint
from backend.api.auth import auth_bp
from backend.api.keys import keys_bp
from backend.api.files import files_bp
from backend.api.scan import scan_bp

# Create blueprints for different API sections
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Root endpoint."""
    return {'message': 'VirusTotal File Scanner API'}, 200

def register_blueprints(app: Flask) -> None:
    """
    Register all blueprints with the Flask application.
    
    Args:
        app: Flask application instance
    """
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(scan_bp)
    
    # Log registered blueprints
    app.logger.info(f"Registered blueprints: {', '.join([bp.name for bp in app.blueprints.values()])}")