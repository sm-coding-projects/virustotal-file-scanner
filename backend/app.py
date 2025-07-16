"""
Main Flask application module for VirusTotal File Scanner.
"""
import os
from flask import Flask
from flask_cors import CORS
from backend.config.config import Config
from backend.config.logging_config import configure_logging
from backend.api.routes import register_blueprints
from backend.models.database import db, migrate

def create_app(config_class=Config):
    """
    Create and configure the Flask application.
    
    Args:
        config_class: Configuration class to use
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app)
    
    # Configure logging
    configure_logging(app)
    
    # Register blueprints
    register_blueprints(app)
    
    @app.route('/health')
    def health_check():
        """Health check endpoint for Docker."""
        return {'status': 'healthy'}, 200
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))